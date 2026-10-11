import type { McpServer } from "./schema";
import type { TraceEvent } from "./trace";
import type { TraceSessionSummary } from "./trace-store";
import { declaredServerFor, isAgentConfigPath, type DeclaredContext, type TraceFinding } from "./trace-heuristics";

// "Resources touched" summary and the text export of a session trace
// (docs/session-trace.md §10). The export is NOT counts-only — it carries
// paths, hosts and commands — so its header says not to paste it off-machine.

export const TRACE_CAVEAT =
  "observations of tool invocations and file-state deltas — not enforcement, not rule attribution; any local process can post events.";
export const FS_WINDOW_CAVEAT =
  "Changes during the session window, including your own edits, git and build output; a change is matched to a tool call only when a write event names the same path.";

export interface ResourceSummary {
  files: Array<{ path: string; writes: number; configFile: boolean }>;
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
    files: [...files.entries()].map(([path, writes]) => ({ path, writes, configFile: isAgentConfigPath(path) })).sort((a, b) => a.path.localeCompare(b.path)),
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

const hhmmss = (iso: string) => iso.slice(11, 19);
const home = process.env.HOME ?? "";
const short = (p: string | null) => (p && home && p.startsWith(home) ? "~" + p.slice(home.length) : (p ?? ""));

export function renderTraceText(summary: TraceSessionSummary, events: TraceEvent[], resources: ResourceSummary, findings: TraceFinding[]): string {
  const lines: string[] = [];
  const findingTags = new Map<string, string[]>();
  for (const f of findings) for (const id of f.eventIds) findingTags.set(id, [...(findingTags.get(id) ?? []), f.ruleId]);
  const coverage = Object.keys(summary.confidences).join(" · ");
  lines.push("AgentLens session trace — local record (paths, hosts, commands). Not counts-only: do not paste off-machine.");
  lines.push(`session ${summary.sessionId.slice(0, 8)} · ${summary.platform} · cwd ${short(summary.cwd)} · ${hhmmss(summary.startedAt)}→${summary.endedAt ? hhmmss(summary.endedAt) : "open"} · mode ${summary.permissionMode ?? "unknown"}`);
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
  for (const f of findings) lines.push(`${f.ruleId} ${f.severity}: ${f.title}`);
  lines.push(`caveat: ${TRACE_CAVEAT}`);
  return lines.join("\n");
}
