import { loadRecentEvents } from "@/lib/observed-store";
import { loadDashboardData } from "@/lib/snapshot";
import type { ObservedEvent } from "@/lib/observed";
import type { McpServer } from "@/lib/schema";
import { timeAgo } from "@/lib/format";
import { AutoRefresh } from "./auto-refresh";

export const dynamic = "force-dynamic";
export const metadata = { title: "Live activity" };

const LAUNCH_SNIPPET = `CLAUDE_CODE_ENABLE_TELEMETRY=1 \\
OTEL_METRICS_EXPORTER=none \\
OTEL_LOGS_EXPORTER=otlp \\
OTEL_TRACES_EXPORTER=none \\
OTEL_EXPORTER_OTLP_LOGS_PROTOCOL=http/json \\
OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://127.0.0.1:3000/api/otel/v1/logs \\
OTEL_LOGS_EXPORT_INTERVAL=1000 \\
OTEL_LOG_USER_PROMPTS=0 \\
OTEL_LOG_ASSISTANT_RESPONSES=0 \\
OTEL_LOG_TOOL_DETAILS=0 \\
claude`;

function DecisionBadge({ e }: { e: ObservedEvent }) {
  if (e.decision === "accept") {
    return (
      <span className="badge b-allow">
        <span className="dot" aria-hidden />
        accept
      </span>
    );
  }
  if (e.decision === "reject") {
    return (
      <span className="badge b-deny">
        <span className="dot" aria-hidden />
        reject
      </span>
    );
  }
  return <span className="meta">—</span>;
}

function describe(e: ObservedEvent, resultFor: Map<string, ObservedEvent>): string {
  switch (e.kind) {
    case "decision": {
      const exec = e.toolUseId ? resultFor.get(e.toolUseId) : undefined;
      const execText =
        e.decision === "reject"
          ? "not executed (rejected)"
          : exec
            ? exec.execution?.success === false
              ? `executed, failed${exec.execution.errorType ? ` (${exec.execution.errorType})` : ""}`
              : `executed${exec.execution?.durationMs != null ? ` in ${exec.execution.durationMs} ms` : ""}`
            : "no execution result observed";
      return `${e.toolName ?? "unknown tool"} — ${execText}`;
    }
    case "result":
      return `${e.toolName ?? "unknown tool"} result: ${
        e.execution?.success === false ? "failure" : e.execution?.success === true ? "success" : "unknown"
      }`;
    case "mode_change":
      return `permission mode ${e.modeChange?.from ?? "?"} → ${e.modeChange?.to ?? "?"}${
        e.modeChange?.trigger ? ` (${e.modeChange.trigger})` : ""
      }`;
    case "mcp_connection": {
      const c = e.mcpConnection;
      // server_name is only emitted with OTEL_LOG_TOOL_DETAILS=1 (vendor behavior)
      const name = c?.serverName ?? "(name withheld — detailed mode off)";
      const extra = [c?.transport, c?.scope ? `${c.scope} scope` : null, c?.errorCode ? `error ${c.errorCode}` : null]
        .filter(Boolean)
        .join(" · ");
      return `MCP server ${name}: ${c?.status ?? "unknown"}${extra ? ` (${extra})` : ""}`;
    }
  }
}

/**
 * Correlate an unnamed MCP-connection event with the DECLARED server inventory
 * from the latest snapshot. Interpretation only (SR4) — never rule/name
 * attribution. "dynamic" scope means the server is not in any collected config
 * file at all, which is itself a signal worth surfacing.
 */
function mcpCorrelation(e: ObservedEvent, declared: McpServer[] | null): string | null {
  const c = e.mcpConnection;
  if (e.kind !== "mcp_connection" || !c || c.serverName) return null;
  if (c.scope === "dynamic") {
    return "not declared in any collected config file — registered at runtime (plugin/host/session-added)";
  }
  if (!declared || !c.transport) return null;
  const names = [...new Set(declared.filter((s) => s.transport === c.transport).map((s) => s.name))];
  if (names.length === 0) return `no declared ${c.transport} server in the latest snapshot`;
  return `declared ${c.transport} server${names.length > 1 ? "s" : ""} in latest snapshot (candidates, interpretation only): ${names.join(", ")}`;
}

export default async function LiveActivity() {
  const feed = await loadRecentEvents(150);
  // Declared MCP inventory for correlation — real snapshots only, never the
  // demo fixture (fixture names would masquerade as candidates).
  let declaredServers: McpServer[] | null = null;
  try {
    const { current } = await loadDashboardData();
    if (!current.isFixture) declaredServers = current.snapshot.mcpServers;
  } catch {
    declaredServers = null;
  }
  const resultFor = new Map<string, ObservedEvent>();
  for (const e of feed.events) {
    if (e.kind === "result" && e.toolUseId) resultFor.set(e.toolUseId, e);
  }
  // Timeline shows decisions, mode changes and MCP connections; raw result
  // events are folded into their decision row via tool_use_id.
  const timeline = feed.events.filter((e) => e.kind !== "result");
  const sessions = new Set(feed.events.map((e) => e.sessionId).filter(Boolean));

  return (
    <main>
      <AutoRefresh seconds={5} />
      <h1>Observed permission activity</h1>
      <p className="meta">
        Evidence classes: <b>decided</b> and <b>executed</b> come from documented Claude Code
        telemetry events; they do not identify which configured rule matched (source category
        only). Absence of events is not proof of inactivity — telemetry may be off.
      </p>

      {feed.lastEventAt ? (
        <div className="notice">
          Receiver active · last event {timeAgo(feed.lastEventAt)} · {sessions.size} session
          {sessions.size === 1 ? "" : "s"} observed · confidence: all events{" "}
          <span className="pill">vendor-event</span>
          {feed.invalidLines > 0 && <> · {feed.invalidLines} unreadable stored lines</>}
          {feed.droppedAtCap > 0 && <> · ⚠️ {feed.droppedAtCap} events dropped at segment cap</>}
        </div>
      ) : (
        <div className="notice notice-warn">
          <b>No events received yet.</b> The receiver listens at{" "}
          <code>POST http://127.0.0.1:3000/api/otel/v1/logs</code> (loopback only). Launch Claude
          Code with telemetry directed at it — AgentLens never writes this configuration for you:
          <pre style={{ overflowX: "auto", fontSize: 12.5, lineHeight: 1.5, marginBottom: 0 }}>
            {LAUNCH_SNIPPET}
          </pre>
        </div>
      )}

      <h2>Timeline ({timeline.length})</h2>
      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Kind</th>
              <th>Decision</th>
              <th>What was observed</th>
              <th className="hide-sm">Decision source</th>
              <th className="hide-sm">Session</th>
            </tr>
          </thead>
          <tbody>
            {timeline.map((e) => (
              <tr key={e.eventId}>
                <td className="meta">{timeAgo(e.eventAt)}</td>
                <td>
                  <span className="pill">{e.kind.replace("_", " ")}</span>
                </td>
                <td>
                  <DecisionBadge e={e} />
                </td>
                <td>
                  {describe(e, resultFor)}
                  {mcpCorrelation(e, declaredServers) && (
                    <div className="meta">{mcpCorrelation(e, declaredServers)}</div>
                  )}
                </td>
                <td className="hide-sm">
                  {e.decisionSource ? <code>{e.decisionSource}</code> : <span className="meta">—</span>}
                </td>
                <td className="hide-sm meta">{e.sessionId ? e.sessionId.slice(0, 8) : "—"}</td>
              </tr>
            ))}
            {timeline.length === 0 && (
              <tr>
                <td colSpan={6} className="meta">
                  No observed events in the last two daily segments.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {timeline.some((e) => e.kind === "mcp_connection" && !e.mcpConnection?.serverName) && (
        <p className="meta" style={{ marginTop: 14 }}>
          MCP server names are withheld by Claude Code under the default privacy mode. To identify
          a specific failing server, relaunch once with <code>OTEL_LOG_TOOL_DETAILS=1</code> —
          knowingly: that mode also exports tool arguments (see{" "}
          <code>docs/testing-live-tracking.md</code>).
        </p>
      )}

      <p className="meta" style={{ marginTop: 14 }}>
        Events are stored locally in <code>data/observed/</code> (gitignored, 7-day retention,
        size-capped) with identity attributes dropped and values redacted at ingest. A decision
        labeled <code>config</code> means Claude Code&apos;s own evaluator decided from
        configuration/runtime state — AgentLens never claims which specific rule matched.
      </p>
    </main>
  );
}
