import Link from "next/link";
import { loadDashboardData } from "@/lib/snapshot";
import { loadTraceEvents, summarizeSessions } from "@/lib/trace-store";
import { traceFindings, type DeclaredContext } from "@/lib/trace-heuristics";
import { shortPath, timeAgo } from "@/lib/format";
import { TRACE_CAVEAT } from "@/lib/trace-render";

export const dynamic = "force-dynamic";
export const metadata = { title: "Sessions" };

export default async function Sessions() {
  const [{ events, invalidLines, droppedAtCap }, { current }] = await Promise.all([loadTraceEvents(), loadDashboardData()]);
  const declared: DeclaredContext | null = current.isFixture
    ? null
    : { instances: current.snapshot.instances, mcpServers: current.snapshot.mcpServers, findings: current.snapshot.findings };
  const sessions = summarizeSessions(events);
  const bySession = new Map<string, typeof events>();
  for (const e of events) if (e.sessionId) bySession.set(e.sessionId, [...(bySession.get(e.sessionId) ?? []), e]);

  return (
    <main>
      <h1>Session traces ({sessions.length})</h1>
      <p className="meta">
        Per-session records of the resources an agent session touched, from vendor hook events you
        enabled for that session (<code>npm run qa -- claude &lt;recipe&gt;</code>, or{" "}
        <code>claude --settings &quot;$(agentlens hook-settings)&quot;</code>) and from explicit
        transcript imports. Coverage legend: <span className="pill">vendor-event</span> hook event ·{" "}
        <span className="pill">derived</span> parsed from a command string ·{" "}
        <span className="pill">observed-on-disk</span> file-state delta over the session window ·{" "}
        <span className="pill">inferred-transcript</span> imported. Localhost origin is not
        authenticity: any local process can post events. Absence of events is not proof of inactivity.
      </p>
      {sessions.length === 0 ? (
        <div className="notice">
          <b>No session traces yet.</b> Start a traced session with{" "}
          <code>npm run qa -- claude drift-playground</code>, or run{" "}
          <code>agentlens hook-settings</code> and pass its output to <code>claude --settings</code>.
          Hooks apply to that process only; AgentLens writes no settings.
        </div>
      ) : (
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                <th>Session</th>
                <th>Platform</th>
                <th className="hide-sm">Working directory</th>
                <th>Started</th>
                <th>Mode</th>
                <th>Writes</th>
                <th>Shell</th>
                <th>Web</th>
                <th>MCP</th>
                <th className="hide-sm">Skills</th>
                <th className="hide-sm">Deps</th>
                <th className="hide-sm">Disk</th>
                <th>Observed findings</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => {
                const findings = traceFindings(s.sessionId, bySession.get(s.sessionId) ?? [], declared);
                return (
                  <tr key={s.sessionId}>
                    <td>
                      <Link href={`/sessions/${encodeURIComponent(s.sessionId)}`}><code>{s.sessionId.slice(0, 8)}</code></Link>
                      {s.endedAt ? null : <span className="meta"> · open</span>}
                    </td>
                    <td>{s.platform}</td>
                    <td className="hide-sm"><code>{shortPath(s.cwd ?? "")}</code></td>
                    <td className="meta">{timeAgo(s.startedAt)}</td>
                    <td>{s.permissionMode ? <code>{s.permissionMode}</code> : <span className="meta">—</span>}</td>
                    <td>{s.counts["file-write"]}</td>
                    <td>{s.counts.shell}</td>
                    <td>{s.counts.web}</td>
                    <td>{s.counts["mcp-call"]}</td>
                    <td className="hide-sm">{s.counts.skill}</td>
                    <td className="hide-sm">{s.counts.dependency}</td>
                    <td className="hide-sm">{s.counts["fs-change"]}</td>
                    <td>{findings.length > 0 ? <b>{findings.length}</b> : <span className="meta">0</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {(invalidLines > 0 || droppedAtCap > 0) && (
        <p className="meta">
          {invalidLines > 0 ? `${invalidLines} stored line(s) failed validation. ` : ""}
          {droppedAtCap > 0 ? `${droppedAtCap} event(s) dropped at the daily size cap.` : ""}
        </p>
      )}
      <p className="meta">Caveat: {TRACE_CAVEAT}</p>
    </main>
  );
}
