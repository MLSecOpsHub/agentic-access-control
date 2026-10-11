import Link from "next/link";
import { notFound } from "next/navigation";
import { loadDashboardData } from "@/lib/snapshot";
import { loadTraceSession } from "@/lib/trace-store";
import { traceFindings, type DeclaredContext } from "@/lib/trace-heuristics";
import { FS_WINDOW_CAVEAT, summarizeResources, TRACE_CAVEAT } from "@/lib/trace-render";
import { shortPath, timeAgo } from "@/lib/format";
import { SeverityBadge } from "../../components";

export const dynamic = "force-dynamic";
export const metadata = { title: "Session trace" };

const hhmmss = (iso: string) => iso.slice(11, 19);

export default async function SessionTrace({ params }: { params: Promise<{ id: string }> }) {
  const { id: rawId } = await params;
  const id = decodeURIComponent(rawId);
  const [session, { current }] = await Promise.all([loadTraceSession(id), loadDashboardData()]);
  if (!session) notFound();
  const declared: DeclaredContext | null = current.isFixture
    ? null
    : { instances: current.snapshot.instances, mcpServers: current.snapshot.mcpServers, findings: current.snapshot.findings };
  const { summary, events } = session;
  const resources = summarizeResources(events, declared);
  const findings = traceFindings(id, events, declared);
  const tags = new Map<string, string[]>();
  for (const f of findings) for (const e of f.eventIds) tags.set(e, [...(tags.get(e) ?? []), f.ruleId]);
  const timeline = events.filter((e) => e.kind !== "fs-change" && e.kind !== "session-start" && e.kind !== "session-end");
  const readsOn = events.some((e) => e.kind === "file-read");

  return (
    <main>
      <p className="meta"><Link href="/sessions">← Sessions</Link></p>
      <h1>
        Session <code>{id.slice(0, 8)}</code> <span className="pill">{summary.platform}</span>
      </h1>
      <p className="meta">
        cwd <code>{shortPath(summary.cwd ?? "")}</code> · started {timeAgo(summary.startedAt)} ({hhmmss(summary.startedAt)}) ·{" "}
        {summary.endedAt ? <>ended {hhmmss(summary.endedAt)}</> : <>no session-end received</>} · mode{" "}
        <code>{summary.permissionMode ?? "unknown"}</code> · {summary.eventCount} events · coverage:{" "}
        {Object.entries(summary.confidences).map(([c, n]) => (
          <span key={c} className="pill">{c} {n}</span>
        ))}{" "}
        · reads {readsOn ? "on" : "off"}
      </p>
      <p className="meta">
        Text export: <code>agentlens trace print {id.slice(0, 8)}…</code> — it carries paths, hosts and
        commands; it is not the counts-only share card. {declared ? null : "No real snapshot is loaded, so declared-config joins are off."}
      </p>

      <h2>Observed findings ({findings.length})</h2>
      {findings.length > 0 ? (
        <div className="tablewrap">
          <table>
            <thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th className="hide-sm">Evidence</th></tr></thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id}>
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td><code>{f.ruleId}</code></td>
                  <td>{f.title}</td>
                  <td className="hide-sm"><code>{f.evidence}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="meta">No observed finding matches this session&apos;s events.</p>
      )}

      <h2>Resources touched</h2>
      <div className="tablewrap">
        <table>
          <tbody>
            <tr>
              <th>Files written ({resources.files.length})</th>
              <td>
                {resources.files.length === 0 ? <span className="meta">none</span> : resources.files.map((f) => (
                  <div key={f.path}><code>{f.path}</code>{f.writes > 1 ? <span className="meta"> ×{f.writes}</span> : null}{f.configFile ? <span className="pill"> agent config</span> : null}</div>
                ))}
              </td>
            </tr>
            <tr>
              <th>Hosts ({resources.hosts.length})</th>
              <td>
                {resources.hosts.length === 0 ? <span className="meta">none</span> : resources.hosts.map((h) => (
                  <div key={`${h.via}:${h.host}`}><code>{h.host}</code> <span className="meta">×{h.count}{h.via === "shell" ? " · parsed from a command" : ""}</span></div>
                ))}
              </td>
            </tr>
            <tr>
              <th>MCP servers ({resources.mcp.length})</th>
              <td>
                {resources.mcp.length === 0 ? <span className="meta">none</span> : resources.mcp.map((m) => (
                  <div key={m.server}>
                    <code>{m.server}</code> <span className="meta">×{m.calls} · {m.tools.join(", ") || "tool names withheld"}</span>{" "}
                    {m.declared ? (
                      <span className="meta">· declared in <code>{shortPath(m.declared.sourceFile)}</code> · enablement {m.declared.enablement ?? "null"}</span>
                    ) : (
                      <span className="pill">not declared in any collected config</span>
                    )}
                  </div>
                ))}
              </td>
            </tr>
            <tr>
              <th>Skills ({resources.skills.length})</th>
              <td>{resources.skills.length === 0 ? <span className="meta">none</span> : resources.skills.map((s) => <div key={s.name}><code>{s.name}</code> <span className="meta">×{s.count}</span></div>)}</td>
            </tr>
            <tr>
              <th>Dependencies ({resources.dependencies.length})</th>
              <td>{resources.dependencies.length === 0 ? <span className="meta">none</span> : resources.dependencies.map((d) => <div key={d.spec}><code>{d.spec}</code> {d.pinned ? <span className="meta">pinned</span> : <span className="pill">unpinned</span>}</div>)}</td>
            </tr>
            <tr>
              <th>Subagents</th>
              <td>{resources.subagents.length === 0 ? <span className="meta">none</span> : resources.subagents.map((s) => <div key={s.type}><code>{s.type}</code> <span className="meta">×{s.count}</span></div>)}</td>
            </tr>
            {readsOn ? (
              <tr>
                <th>Reads by directory</th>
                <td>{resources.reads.map((r) => <div key={r.dir}><code>{r.dir}</code> <span className="meta">×{r.count}</span></div>)}</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      <h2>On-disk window ({resources.fsChanges.length})</h2>
      <p className="meta">{FS_WINDOW_CAVEAT}</p>
      {resources.fsChanges.length > 0 ? (
        <ul className="notes">
          {resources.fsChanges.map((c) => (
            <li key={c.path}><code>{c.path}</code> <span className="meta">{c.change}{c.matchedWrite ? " · matches a write event" : c.change === "touched" ? "" : " · no matching write event"}</span></li>
          ))}
        </ul>
      ) : summary.endedAt ? (
        <p className="meta">No file-state delta recorded (the working directory was outside the scanned roots, hit the walk caps, or did not change).</p>
      ) : (
        <p className="meta">Computed when the session ends; if it never sent one, <code>agentlens trace close {id.slice(0, 8)}…</code> closes it.</p>
      )}

      <h2>Timeline ({timeline.length})</h2>
      <div className="tablewrap">
        <table>
          <thead><tr><th>Time</th><th>Kind</th><th>Resource</th><th>Outcome</th><th className="hide-sm">Prompt</th><th className="hide-sm">Agent</th><th>Confidence</th></tr></thead>
          <tbody>
            {timeline.map((e) => (
              <tr key={e.eventId}>
                <td className="meta">{hhmmss(e.eventAt)}</td>
                <td><span className="pill">{e.confidence === "derived" ? "└ " : ""}{e.kind}</span></td>
                <td><code>{e.resource}</code>{tags.get(e.eventId)?.map((t) => <code key={t}> {t}</code>)}</td>
                <td className="meta">{e.kind === "shell" && typeof e.detail.exitCode === "number" ? `exit ${e.detail.exitCode}` : e.outcome}</td>
                <td className="hide-sm meta">{e.promptId ? e.promptId.slice(0, 8) : "—"}</td>
                <td className="hide-sm meta">{e.agentType ?? (e.agentId ? e.agentId.slice(0, 8) : "—")}</td>
                <td><span className="pill">{e.confidence}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="meta">Caveat: {TRACE_CAVEAT}</p>
    </main>
  );
}
