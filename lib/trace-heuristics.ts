import type { AgentInstance, McpServer, RiskFinding, Severity } from "./schema";
import type { TraceEvent } from "./trace";
import { PIPE_TO_SHELL } from "./heuristics";
import { HOME_OR_CONFIG_PATH } from "./scenario-catalog";
import { classifyEvent, type Promotion } from "./shell-classes";

// Observed findings over a session trace (docs/session-trace.md §12). A
// separate type from RiskFinding on purpose: these describe invocations and
// file-state deltas in ONE session, never enter snapshots or `check`, and
// never claim which rule permitted anything (SR4).

export type TraceRuleId = "O1" | "O2" | "O3" | "O4" | "O5" | "O6";

export interface TraceFinding {
  id: string;
  ruleId: TraceRuleId;
  severity: Severity;
  title: string;
  evidence: string;
  sessionId: string;
  eventIds: string[];
}

export interface DeclaredContext {
  instances: AgentInstance[];
  mcpServers: McpServer[];
  findings: RiskFinding[];
}

export const AGENT_CONFIG_PATH =
  /(^|\/)(\.claude\/settings(\.local)?\.json|\.mcp\.json|\.claude\.json|\.gemini\/(settings|trustedFolders)\.json|\.codex\/config\.toml|managed-settings\.json|\.claude\/hooks\/[^/]+|\.claude\/skills\/.+)$/;

export const isAgentConfigPath = (p: string) => AGENT_CONFIG_PATH.test(p);

// The declared instance a session most plausibly ran under: the project whose
// path contains the session cwd (longest match), else the user instance.
export function instanceForCwd(cwd: string | null, instances: AgentInstance[], platform: TraceEvent["platform"]): AgentInstance | null {
  const same = instances.filter((i) => i.platform === platform);
  if (cwd) {
    const projects = same
      .filter((i) => i.projectPath && (cwd === i.projectPath || cwd.startsWith(i.projectPath + "/")))
      .sort((a, b) => (b.projectPath?.length ?? 0) - (a.projectPath?.length ?? 0));
    if (projects[0]) return projects[0];
  }
  return same.find((i) => i.scope === "user") ?? null;
}

export function declaredServerFor(name: string, cwd: string | null, declared: DeclaredContext | null, platform: TraceEvent["platform"]): McpServer | null {
  if (!declared) return null;
  const inst = instanceForCwd(cwd, declared.instances, platform);
  const candidates = declared.mcpServers.filter((s) => s.name === name);
  return candidates.find((s) => inst && s.instanceId === inst.id) ?? candidates[0] ?? null;
}

const findingFor = (declared: DeclaredContext, srv: McpServer, id: "H3" | "H4", severity?: Severity) =>
  declared.findings.find((f) => f.heuristicId === id && f.sourceFile === srv.sourceFile && f.title.includes(`"${srv.name}"`) && (!severity || f.severity === severity));

export function traceFindings(sessionId: string, events: TraceEvent[], declared: DeclaredContext | null): TraceFinding[] {
  const out: TraceFinding[] = [];
  let n = 0;
  const add = (ruleId: TraceRuleId, severity: Severity, title: string, evidence: string, eventIds: string[]) =>
    out.push({ id: `${ruleId}:${sessionId}:${n++}`, ruleId, severity, title, evidence, sessionId, eventIds });

  const start = events.find((e) => e.kind === "session-start");
  const cwd = start?.cwd ?? events.find((e) => e.cwd)?.cwd ?? null;
  const platform = events[0]?.platform ?? "claude-code";
  const inst = declared ? instanceForCwd(cwd, declared.instances, platform) : null;
  const scratch = typeof start?.detail.transcriptPath === "string" ? null : null; // scratchpad_dir is not projected in v1
  const allowedOutside = new Set<string>([...(inst?.additionalDirectories.map((d) => d.path) ?? []), ...(scratch ? [scratch] : [])]);
  const underAllowed = (p: string) => [...allowedOutside].some((d) => p === d || p.startsWith(d.replace(/\/$/, "") + "/"));

  // O1 — agent configuration touched during the session
  for (const e of events) {
    if ((e.kind === "file-write" || e.kind === "config-change") && isAgentConfigPath(e.resource)) {
      add("O1", "high",
        `A tool call in this session targeted an agent configuration file: ${e.resource} — whether the platform applied it is not observed; re-collect to see the declared result`,
        `${e.kind} · ${e.toolName ?? "config-change"} · ${e.outcome}`, [e.eventId]);
    }
  }
  // O2 — remote content piped to a shell, as observed in a command string
  for (const e of events) {
    if (e.kind === "shell" && PIPE_TO_SHELL.test(e.resource)) {
      add("O2", "medium", "A shell command in this session piped remote content to a shell interpreter (parsed from the command string)", e.resource, [e.eventId]);
    }
  }
  // O3 — package installs
  for (const e of events) {
    if (e.kind === "dependency") {
      const pinned = e.detail.pinned === true;
      const parent = events.find((p) => p.toolUseId === e.toolUseId && p.kind === "shell");
      add("O3", pinned ? "low" : "medium",
        `A package install ran in this session: ${e.resource}${pinned ? "" : " (version unpinned)"}${typeof parent?.detail.exitCode === "number" ? `; exit code ${parent.detail.exitCode}` : ""}`,
        e.resource, [e.eventId]);
    }
  }
  // O4 — MCP servers used, joined to their declared rows
  const byServer = new Map<string, TraceEvent[]>();
  for (const e of events) {
    if (e.kind !== "mcp-call" || typeof e.detail.server !== "string") continue;
    byServer.set(e.detail.server, [...(byServer.get(e.detail.server) ?? []), e]);
  }
  for (const [server, calls] of byServer) {
    const row = declaredServerFor(server, cwd, declared, platform);
    const times = `${calls.length} time${calls.length === 1 ? "" : "s"}`;
    if (!row) {
      add("O4", "info", `MCP server "${server}" was used ${times}; it is not declared in any collected configuration file (invocation matching, not rule attribution)`, calls.map((c) => c.resource).join(", "), calls.map((c) => c.eventId));
      continue;
    }
    const h3 = declared ? findingFor(declared, row, "H3", "high") : undefined;
    const h4 = declared ? findingFor(declared, row, "H4") : undefined;
    const risky = h3 || h4;
    const severity: Severity = risky ? "high" : row.enablement === null ? "medium" : "low";
    if (severity === "low") continue;
    add("O4", severity,
      `MCP server "${server}" was used ${times}; its declared configuration ${risky ? [h3 ? "launches via an unpinned package runner" : null, h4 ? "carries credential env keys" : null].filter(Boolean).join(" and ") : "has no recorded approval choice"} (invocation matching, not rule attribution)`,
      `${row.sourceFile} · enablement ${row.enablement ?? "null"}`, calls.map((c) => c.eventId));
  }
  // O5 — writes outside the working directory or into home/config paths
  for (const e of events) {
    if (e.kind !== "file-write") continue;
    const outside = e.resource.startsWith("/") || e.resource.startsWith("~");
    if ((outside || HOME_OR_CONFIG_PATH.test(e.resource)) && !underAllowed(e.resource) && !isAgentConfigPath(e.resource)) {
      add("O5", "medium", `A write targeted a path outside the session's working directory: ${e.resource}`, `${e.toolName ?? "write"} · ${e.outcome}`, [e.eventId]);
    }
  }
  // O6 — destructive or privileged shell command: the promotion subset of the
  // shell classifier (lib/shell-classes.ts), one finding per command segment.
  // Severity reads the exit code only: "high" needs exit 0 AND an elevated,
  // out-of-tree, credential-path, device or remote-shell/upload shape.
  for (const e of events) {
    if (e.kind !== "shell") continue;
    for (const seg of classifyEvent(e).segments) {
      const promos = seg.promotions.filter((p) => !(p.pattern.endsWith("-outside") && p.target && underAllowed(p.target)));
      if (promos.length === 0) continue;
      const rank = (p: Promotion) => (p.pattern === "sudo-wrapper" ? 1 : 0);
      const ordered = [...promos].sort((a, b) => rank(a) - rank(b));
      const exit = typeof e.detail.exitCode === "number" ? e.detail.exitCode : null;
      const strong = seg.elevated || ordered.some((p) => p.strong);
      const severity: Severity = exit === 0 && strong ? "high" : "medium";
      const segText = seg.text.length > 120 ? seg.text.slice(0, 119) + "…" : seg.text;
      const notes = [...new Set(ordered.map((p) => p.note).filter((n): n is string => typeof n === "string"))];
      add("O6", severity,
        `A shell command in this session declared a ${ordered[0].kind} operation: ${segText} (parsed from the command string; exit code ${exit ?? "not reported"})`,
        [ordered.map((p) => p.pattern).join(", "), seg.text, `exit code ${exit ?? "not reported"}`, ...notes].join(" · "), [e.eventId]);
    }
  }
  return out;
}
