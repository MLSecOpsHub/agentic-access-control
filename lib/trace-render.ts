import type { McpServer } from "./schema";
import type { TraceEvent } from "./trace";
import type { TraceSessionSummary } from "./trace-store";
import { declaredServerFor, isAgentConfigPath, type DeclaredContext, type TraceFinding } from "./trace-heuristics";
import { classifyEvent, shellClassCounts, type ShellClass, type ShellClassCounts } from "./shell-classes";
import { HOME_OR_CONFIG_PATH } from "./scenario-catalog";

// "Resources touched" summary and the text export of a session trace
// (docs/session-trace.md §10). The export is NOT counts-only — it carries
// paths, hosts and commands — so its header says not to paste it off-machine.

export const TRACE_CAVEAT =
  "observations of tool invocations and file-state deltas — not enforcement, not rule attribution; any local process can post events.";
export const FS_WINDOW_CAVEAT =
  "Changes during the session window, including your own edits, git and build output; a change is matched to a tool call only when a write event names the same path.";

export interface ResourceSummary {
  files: Array<{ path: string; writes: number; configFile: boolean; outsideCwd: boolean }>;
  shell: ShellClassCounts & { commands: Array<{ eventId: string; text: string; classes: ShellClass[]; exitCode: number | null; promoted: string[] }> };
  hosts: Array<{ host: string; count: number; via: "tool" | "shell" }>;
  mcp: Array<{ server: string; calls: number; tools: string[]; declared: McpServer | null }>;
  skills: Array<{ name: string; count: number }>;
  dependencies: Array<{ spec: string; pinned: boolean }>;
  fsChanges: Array<{ path: string; change: string; matchedWrite: boolean }>;
  reads: Array<{ dir: string; count: number }>;
  subagents: Array<{ type: string; count: number }>;
}

export function summarizeResources(events: TraceEvent[], declared: DeclaredContext | null): ResourceSummary {
  const start = events.find((e) => e.kind === "session-start");
  const cwd = start?.cwd ?? events.find((e) => e.cwd)?.cwd ?? null;
  const platform = events[0]?.platform ?? "claude-code";
  const count = <K extends string>(items: K[]) => {
    const m = new Map<K, number>();
    for (const i of items) m.set(i, (m.get(i) ?? 0) + 1);
    return m;
  };
  const files = count(events.filter((e) => e.kind === "file-write").map((e) => e.resource));
  const hostsTool = count(events.filter((e) => e.kind === "web" && e.confidence !== "derived").map((e) => e.resource));
  const hostsShell = count(events.filter((e) => e.kind === "web" && e.confidence === "derived").map((e) => e.resource));
  const mcp = new Map<string, { calls: number; tools: Set<string> }>();
  for (const e of events) {
    if (e.kind !== "mcp-call") continue;
    const server = typeof e.detail.server === "string" ? e.detail.server : "?";
    const m = mcp.get(server) ?? { calls: 0, tools: new Set<string>() };
    m.calls++;
    if (typeof e.detail.tool === "string") m.tools.add(e.detail.tool);
    mcp.set(server, m);
  }
  const deps = new Map<string, boolean>();
  for (const e of events) if (e.kind === "dependency") deps.set(e.resource, e.detail.pinned === true);
  return {
    files: [...files.entries()].map(([path, writes]) => ({ path, writes, configFile: isAgentConfigPath(path), outsideCwd: path.startsWith("/") || path.startsWith("~") || path.startsWith("../") || HOME_OR_CONFIG_PATH.test(path) })).sort((a, b) => a.path.localeCompare(b.path)),
    shell: {
      ...shellClassCounts(events),
      commands: events.filter((e) => e.kind === "shell").map((e) => {
        const c = classifyEvent(e);
        return { eventId: e.eventId, text: e.resource, classes: c.classes, exitCode: typeof e.detail.exitCode === "number" ? e.detail.exitCode : null, promoted: c.segments.flatMap((s) => s.promotions.map((p) => p.pattern)) };
      }),
    },
    hosts: [
      ...[...hostsTool.entries()].map(([host, n]) => ({ host, count: n, via: "tool" as const })),
      ...[...hostsShell.entries()].map(([host, n]) => ({ host, count: n, via: "shell" as const })),
    ],
    mcp: [...mcp.entries()].map(([server, m]) => ({ server, calls: m.calls, tools: [...m.tools].sort(), declared: declaredServerFor(server, cwd, declared, platform) })),
    skills: [...count(events.filter((e) => e.kind === "skill").map((e) => e.resource)).entries()].map(([name, n]) => ({ name, count: n })),
    dependencies: [...deps.entries()].map(([spec, pinned]) => ({ spec, pinned })),
    fsChanges: events.filter((e) => e.kind === "fs-change").map((e) => ({ path: e.resource, change: String(e.detail.change ?? "?"), matchedWrite: e.detail.matchedWrite === true })),
    reads: [...count(events.filter((e) => e.kind === "file-read").map((e) => e.resource)).entries()].map(([dir, n]) => ({ dir, count: n })).sort((a, b) => b.count - a.count),
    subagents: [...count(events.filter((e) => e.kind === "subagent" && e.detail.phase !== "stop").map((e) => e.resource)).entries()].map(([type, n]) => ({ type, count: n })),
  };
}

/** What each count on /sessions refers to (header tooltips and the legend). */
export const COLUMN_TEXT = {
  mode: "The Claude Code permission mode the session reported in its hook payloads — the gate every row passed through (under auto a classifier approved actions; under acceptEdits writes needed no prompt; under bypassPermissions nothing did). Reported by the session, not read from a settings file; a session can change mode mid-way (Shift+Tab).",
  writes: "File-write tool calls (Write/Edit/MultiEdit/NotebookEdit); paths relative to the working directory; file contents are never recorded.",
  shell: "Bash tool calls: the command string (redacted, truncated) and the exit code when the platform reported one. Classes are parsed from the string by program and arguments — the command was declared; only the exit code says whether it ran.",
  web: "WebFetch/WebSearch calls plus URLs parsed from command strings (marked cmd); scheme, host and path only — never query strings.",
  mcp: "mcp__server__tool calls: server and tool names only, never arguments; joined to the declared MCP inventory (undeclared = not in any collected config).",
  skills: "Skill tool calls; names only.",
  deps: "Package installs parsed from command strings (derived); pinned when the spec carries a version.",
  disk: "Files changed in the working directory between session start and end — includes your own edits, git and build output; computed when the session ends, and only for directories AgentLens has already scanned.",
  findings: "Observed findings O1–O6 over this session's events: O1 agent-config write · O2 remote content piped to a shell · O3 package install · O4 MCP server used (joined to its declared risk) · O5 write outside the working directory · O6 destructive or privileged shell command.",
} as const;

export interface ColumnCell { n: string | number; sub: string | null; flagged?: boolean }
export interface ColumnSummaries { writes: ColumnCell; shell: ColumnCell; web: ColumnCell; mcp: ColumnCell; skills: ColumnCell; deps: ColumnCell; disk: ColumnCell; findings: ColumnCell }

// Join items into a short sub-line: as many as fit in `max` characters, then "+n more".
export function joinShort(items: string[], max = 44): string | null {
  if (items.length === 0) return null;
  const parts: string[] = [];
  let len = 0;
  for (const it of items) {
    if (parts.length > 0 && len + 3 + it.length > max) break;
    parts.push(it);
    len += (parts.length > 1 ? 3 : 0) + it.length;
  }
  const rest = items.length - parts.length;
  return parts.join(" · ") + (rest > 0 ? ` +${rest} more` : "");
}

const hostOf = (u: string) => { try { return new URL(u).host; } catch { return u; } };

export function columnSummaries(summary: TraceSessionSummary, resources: ResourceSummary, findings: TraceFinding[]): ColumnSummaries {
  const files = resources.files.map((f) => `${f.path}${f.configFile ? " ⚠ agent config" : f.outsideCwd ? " (outside cwd)" : ""}`);
  const shellParts = [
    ...resources.shell.byClass.map((b) => `${b.cls} ×${b.count}`),
    ...(resources.shell.other > 0 ? [`other ×${resources.shell.other}`] : []),
    ...(resources.shell.failed > 0 ? [`${resources.shell.failed} failed`] : []),
  ];
  const hostSeen = new Set<string>();
  const hosts: string[] = [];
  for (const h of resources.hosts) {
    const name = h.host === "web-search" ? "web-search" : hostOf(h.host);
    if (hostSeen.has(name)) continue;
    hostSeen.add(name);
    hosts.push(h.via === "shell" ? `${name} (cmd)` : name);
  }
  const mcp = resources.mcp.map((m) => `${m.server} ×${m.calls}${m.declared ? "" : " (undeclared)"}`);
  const deps = resources.dependencies.map((d) => `${d.spec}${d.pinned ? "" : " (unpinned)"}`);
  const byRule = new Map<string, number>();
  for (const f of findings) byRule.set(f.ruleId, (byRule.get(f.ruleId) ?? 0) + 1);
  const fsym: Record<string, string> = { added: "+", modified: "~", touched: "·", removed: "-" };
  const fsCount = new Map<string, number>();
  for (const c of resources.fsChanges) fsCount.set(c.change, (fsCount.get(c.change) ?? 0) + 1);
  const unmatched = resources.fsChanges.filter((c) => !c.matchedWrite && c.change !== "touched").length;
  const disk: ColumnCell = !summary.endedAt
    ? { n: "pending", sub: "computed at session end" }
    : resources.fsChanges.length === 0
      ? { n: 0, sub: "no delta recorded" }
      : { n: resources.fsChanges.length, sub: [...fsCount.entries()].map(([k, v]) => `${fsym[k] ?? "?"}${v}`).join(" ") + (unmatched > 0 ? ` · ${unmatched} unmatched` : "") };
  return {
    writes: { n: summary.counts["file-write"], sub: joinShort(files), flagged: resources.files.some((f) => f.configFile) },
    shell: { n: summary.counts.shell, sub: joinShort(shellParts, 60) },
    web: { n: summary.counts.web, sub: joinShort(hosts) },
    mcp: { n: summary.counts["mcp-call"], sub: joinShort(mcp), flagged: resources.mcp.some((m) => !m.declared) },
    skills: { n: summary.counts.skill, sub: joinShort(resources.skills.map((s) => s.name)) },
    deps: { n: summary.counts.dependency, sub: joinShort(deps), flagged: resources.dependencies.some((d) => !d.pinned) },
    disk,
    findings: { n: findings.length, sub: joinShort([...byRule.entries()].sort().map(([r, n]) => `${r} ×${n}`)), flagged: findings.some((f) => f.severity === "high" || f.severity === "critical") },
  };
}

/** `auto`, or `default → auto` when the session changed mode; null when no event carried one. */
export function modeLabel(summary: TraceSessionSummary): string | null {
  if (summary.permissionModes.length === 0) return summary.permissionMode;
  return summary.permissionModes.join(" → ");
}

const hhmmss = (iso: string) => iso.slice(11, 19);
const home = process.env.HOME ?? "";
const short = (p: string | null) => (p && home && p.startsWith(home) ? "~" + p.slice(home.length) : (p ?? ""));

export function renderTraceText(summary: TraceSessionSummary, events: TraceEvent[], resources: ResourceSummary, findings: TraceFinding[]): string {
  const lines: string[] = [];
  const findingTags = new Map<string, string[]>();
  for (const f of findings) for (const id of f.eventIds) findingTags.set(id, [...(findingTags.get(id) ?? []), f.ruleId]);
  const coverage = Object.keys(summary.confidences).join(" · ");
  lines.push("AgentLens session trace — local record (paths, hosts, commands). Not counts-only: do not paste off-machine.");
  lines.push(`session ${summary.sessionId.slice(0, 8)} · ${summary.platform} · cwd ${short(summary.cwd)} · ${hhmmss(summary.startedAt)}→${summary.endedAt ? hhmmss(summary.endedAt) : "open"} · mode ${modeLabel(summary) ?? "unknown"}${summary.permissionModeChanges > 0 ? ` (changed ${summary.permissionModeChanges}×)` : ""}`);
  lines.push(`coverage: ${coverage}${events.some((e) => e.kind === "file-read") ? " · reads: on" : " · reads: off"}`);
  let prompt: string | null | undefined = undefined;
  let promptNo = 0;
  for (const e of events) {
    if (e.kind === "fs-change" || e.kind === "session-start" || e.kind === "session-end") continue;
    if (e.promptId !== prompt) {
      prompt = e.promptId;
      promptNo++;
      lines.push(`#${promptNo} prompt ${prompt ? prompt.slice(0, 8) : "—"}`);
    }
    const indent = e.agentId ? "    " : "  ";
    const tags = findingTags.get(e.eventId)?.join(" ") ?? "";
    const outcome = e.kind === "shell" && typeof e.detail.exitCode === "number" ? `exit ${e.detail.exitCode}` : e.outcome !== "ok" ? e.outcome : "";
    const prefix = e.confidence === "derived" ? "└ " : "";
    lines.push(`${indent}${hhmmss(e.eventAt)} ${(prefix + e.kind).padEnd(13)} ${e.resource.padEnd(48)} ${outcome.padEnd(8)} ${e.confidence}${tags ? "  " + tags : ""}`.trimEnd());
  }
  if (resources.fsChanges.length > 0) {
    const sym: Record<string, string> = { added: "+", modified: "~", touched: "·", removed: "-" };
    lines.push(`on-disk window: ${resources.fsChanges.map((c) => `${sym[c.change] ?? "?"}${c.path}`).join(" ")}`);
    const unmatched = resources.fsChanges.filter((c) => !c.matchedWrite && c.change !== "touched");
    if (unmatched.length > 0) lines.push(`  ${unmatched.length} changed path${unmatched.length === 1 ? "" : "s"} without a matching write event: ${unmatched.map((c) => c.path).join(", ")}`);
  }
  if (resources.shell.total > 0) {
    lines.push(`shell by class: ${[...resources.shell.byClass.map((b) => `${b.cls} ${b.count}`), ...(resources.shell.other > 0 ? [`other ${resources.shell.other}`] : [])].join(" · ")}${resources.shell.failed > 0 ? ` · ${resources.shell.failed} with non-zero exit` : ""} (parsed from command strings)`);
  }
  for (const f of findings) lines.push(`${f.ruleId} ${f.severity}: ${f.title}`);
  lines.push(`caveat: ${TRACE_CAVEAT}`);
  return lines.join("\n");
}
