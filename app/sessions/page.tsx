import Link from "next/link";
import { loadDashboardData } from "@/lib/snapshot";
import { loadTraceEvents, summarizeSessions, type TraceSessionSummary } from "@/lib/trace-store";
import { traceFindings, type DeclaredContext } from "@/lib/trace-heuristics";
import { shortPath, timeAgo } from "@/lib/format";
import { COLUMN_TEXT, columnSummaries, summarizeResources, TRACE_CAVEAT, type ColumnCell } from "@/lib/trace-render";
import { MODE_MISSING_TEXT, MODE_TEXT } from "@/lib/mode-text";
import { SHELL_CLASS_TEXT, SHELL_CLASSES } from "@/lib/shell-classes";
import { ModeBadge } from "../components";

export const dynamic = "force-dynamic";
export const metadata = { title: "Sessions" };

function Cell({ id, anchor, cell, hide }: { id: string; anchor: string; cell: ColumnCell; hide?: boolean }) {
  const zero = cell.n === 0;
  return (
    <td className={hide ? "hide-sm" : undefined}>
      {zero ? <span className="meta">0</span> : <Link href={`/sessions/${encodeURIComponent(id)}#${anchor}`}>{cell.flagged ? <b>{cell.n}</b> : cell.n}</Link>}
      {cell.sub ? <span className="cell-sub" title={cell.sub}>{cell.sub}</span> : null}
    </td>
  );
}

function ModeCell({ s }: { s: TraceSessionSummary }) {
  if (!s.permissionMode) return <span className="meta" title={MODE_MISSING_TEXT}>—</span>;
  if (s.permissionModes.length <= 1) return <ModeBadge mode={s.permissionMode} />;
  return (
    <>
      {s.permissionModes.map((m, i) => (
        <span key={m}>{i > 0 ? <span className="meta"> → </span> : null}<ModeBadge mode={m} /></span>
      ))}
      <span className="cell-sub">changed ×{s.permissionModeChanges}</span>
    </>
  );
}

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
        transcript imports. Localhost origin is not authenticity: any local process can post events.
        Absence of events is not proof of inactivity.
      </p>
      <details className="scenario">
        <summary>What the columns mean</summary>
        <div className="scenario-body">
          <ul>
            <li><b>Mode</b> — {COLUMN_TEXT.mode}
              <ul>
                {Object.entries(MODE_TEXT).map(([m, t]) => <li key={m}><code>{m}</code> {t.slice(t.indexOf(":") + 2)}</li>)}
                <li><code>—</code> {MODE_MISSING_TEXT}</li>
              </ul>
            </li>
            <li><b>Writes</b> — {COLUMN_TEXT.writes}</li>
            <li><b>Shell</b> — {COLUMN_TEXT.shell}
              <ul>
                {SHELL_CLASSES.map((c) => <li key={c}><code>{c}</code> {SHELL_CLASS_TEXT[c]}</li>)}
                <li><code>other</code> commands matching no class (builds, tests, listings, …)</li>
              </ul>
            </li>
            <li><b>Web</b> — {COLUMN_TEXT.web}</li>
            <li><b>MCP</b> — {COLUMN_TEXT.mcp}</li>
            <li><b>Skills</b> — {COLUMN_TEXT.skills}</li>
            <li><b>Deps</b> — {COLUMN_TEXT.deps}</li>
            <li><b>Disk</b> — {COLUMN_TEXT.disk}</li>
            <li><b>Observed findings</b> — {COLUMN_TEXT.findings}</li>
            <li><b>Coverage</b> — <span className="pill">vendor-event</span> hook event ·{" "}
              <span className="pill">derived</span> parsed from a command string ·{" "}
              <span className="pill">observed-on-disk</span> file-state delta over the session window ·{" "}
              <span className="pill">inferred-transcript</span> imported from a transcript you pointed at.</li>
          </ul>
          <p className="meta">Each count links to the matching section of the session page; the line under a count lists what it refers to (first few, then +n more). Bold counts carry a flag: an agent-config write, an undeclared MCP server, an unpinned install, or a high-severity finding.</p>
        </div>
      </details>
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
                <th title={COLUMN_TEXT.mode}>Mode</th>
                <th title={COLUMN_TEXT.writes}>Writes</th>
                <th title={COLUMN_TEXT.shell}>Shell</th>
                <th title={COLUMN_TEXT.web}>Web</th>
                <th title={COLUMN_TEXT.mcp}>MCP</th>
                <th className="hide-sm" title={COLUMN_TEXT.skills}>Skills</th>
                <th className="hide-sm" title={COLUMN_TEXT.deps}>Deps</th>
                <th className="hide-sm" title={COLUMN_TEXT.disk}>Disk</th>
                <th title={COLUMN_TEXT.findings}>Observed findings</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => {
                const own = bySession.get(s.sessionId) ?? [];
                const findings = traceFindings(s.sessionId, own, declared);
                const cols = columnSummaries(s, summarizeResources(own, declared), findings);
                return (
                  <tr key={s.sessionId}>
                    <td>
                      <Link href={`/sessions/${encodeURIComponent(s.sessionId)}`}><code>{s.sessionId.slice(0, 8)}</code></Link>
                      {s.endedAt ? null : <span className="meta"> · open</span>}
                    </td>
                    <td>{s.platform}</td>
                    <td className="hide-sm"><code>{shortPath(s.cwd ?? "")}</code></td>
                    <td className="meta">{timeAgo(s.startedAt)}</td>
                    <td><ModeCell s={s} /></td>
                    <Cell id={s.sessionId} anchor="files" cell={cols.writes} />
                    <Cell id={s.sessionId} anchor="shell" cell={cols.shell} />
                    <Cell id={s.sessionId} anchor="hosts" cell={cols.web} />
                    <Cell id={s.sessionId} anchor="mcp" cell={cols.mcp} />
                    <Cell id={s.sessionId} anchor="skills" cell={cols.skills} hide />
                    <Cell id={s.sessionId} anchor="deps" cell={cols.deps} hide />
                    <Cell id={s.sessionId} anchor="disk" cell={cols.disk} hide />
                    <Cell id={s.sessionId} anchor="findings" cell={cols.findings} />
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
