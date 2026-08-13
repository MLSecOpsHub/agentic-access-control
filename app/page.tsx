import Link from "next/link";
import { loadDashboardData } from "@/lib/snapshot";
import { shortPath, timeAgo } from "@/lib/format";
import {
  EffectBadge,
  ModeBadge,
  SnapshotMeta,
  instanceHref,
  sortFindings,
  SeverityBadge,
} from "./components";

export const dynamic = "force-dynamic";
export const metadata = { title: "Overview" };

export default async function Overview() {
  const { current, drift } = await loadDashboardData();
  const s = current.snapshot;

  const ruleCount = (effect: "allow" | "ask" | "deny") =>
    s.instances.reduce(
      (n, i) => n + i.permissionRules.filter((r) => r.effect === effect).length,
      0,
    );
  const allRules = s.instances.reduce((n, i) => n + i.permissionRules.length, 0);
  const bySev = (sev: string) => s.findings.filter((f) => f.severity === sev).length;
  const topFindings = sortFindings(s.findings).slice(0, 5);

  return (
    <main>
      <h1>Overview</h1>
      <SnapshotMeta current={current} />

      <div className="tiles">
        <div className="tile">
          <div className="label">Agent instances</div>
          <div className="value">{s.instances.length}</div>
          <div className="sub">{new Set(s.instances.map((i) => i.platform)).size} platforms</div>
        </div>
        <div className="tile">
          <div className="label">Permission rules</div>
          <div className="value">{allRules}</div>
          <div className="sub">
            {ruleCount("deny")} deny · {ruleCount("ask")} ask · {ruleCount("allow")} allow
          </div>
        </div>
        <Link href="/mcp" className="tile">
          <div className="label">MCP servers</div>
          <div className="value">{s.mcpServers.length}</div>
          <div className="sub">
            {s.mcpServers.filter((m) => m.transport === "stdio").length} stdio ·{" "}
            {s.mcpServers.filter((m) => m.transport !== "stdio").length} remote
          </div>
        </Link>
        <Link href="/findings" className="tile">
          <div className="label">Risk findings</div>
          <div className="value">{s.findings.length}</div>
          <div className="sub">
            {bySev("critical")} critical · {bySev("high")} high · {bySev("medium")} medium
          </div>
        </Link>
      </div>

      {drift && (
        <>
          <h2>Drift since previous snapshot ({timeAgo(drift.previousAt)})</h2>
          {drift.addedRules.length + drift.removedRules.length + drift.addedServers.length + drift.removedServers.length === 0 ? (
            <p className="meta">No permission or MCP changes.</p>
          ) : (
            <div className="notice notice-warn">
              <b>
                {drift.addedRules.length} rules added, {drift.removedRules.length} removed ·{" "}
                {drift.addedServers.length} MCP servers added, {drift.removedServers.length} removed.
              </b>
              <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                {drift.addedRules.slice(0, 8).map((r, i) => (
                  <li key={`a${i}`}>
                    added <EffectBadge effect={r.effect} /> <code>{r.matcher}</code> on{" "}
                    <Link href={instanceHref(r.instanceId)}>{r.instanceId}</Link>
                  </li>
                ))}
                {drift.removedRules.slice(0, 8).map((r, i) => (
                  <li key={`r${i}`}>
                    removed <EffectBadge effect={r.effect} /> <code>{r.matcher}</code> from{" "}
                    <Link href={instanceHref(r.instanceId)}>{r.instanceId}</Link>
                  </li>
                ))}
                {drift.addedServers.map((m, i) => (
                  <li key={`as${i}`}>
                    added MCP server <code>{m.name}</code> ({m.transport})
                  </li>
                ))}
                {drift.removedServers.map((m, i) => (
                  <li key={`rs${i}`}>
                    removed MCP server <code>{m.name}</code>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}

      <h2>Agent instances</h2>
      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th>Instance</th>
              <th>Scope</th>
              <th className="hide-sm">Project</th>
              <th>Mode</th>
              <th>Rules</th>
              <th>Findings</th>
            </tr>
          </thead>
          <tbody>
            {s.instances.map((inst) => {
              const f = s.findings.filter((x) => x.instanceId === inst.id);
              return (
                <tr key={inst.id}>
                  <td>
                    <Link href={instanceHref(inst.id)}>
                      <b>{inst.platform}</b>
                    </Link>
                    <div className="meta">{inst.id}</div>
                  </td>
                  <td>
                    <span className="pill">{inst.scope}</span>
                  </td>
                  <td className="hide-sm meta">{inst.projectPath ? shortPath(inst.projectPath) : "—"}</td>
                  <td><ModeBadge mode={inst.defaultMode} /></td>
                  <td>{inst.permissionRules.length}</td>
                  <td>{f.length > 0 ? <b>{f.length}</b> : <span className="meta">0</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <h2>
        Top findings · <Link href="/findings" style={{ fontWeight: 400, fontSize: 13 }}>all {s.findings.length}</Link>
      </h2>
      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Finding</th>
              <th className="hide-sm">Instance</th>
            </tr>
          </thead>
          <tbody>
            {topFindings.map((f) => (
              <tr key={f.id}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td>{f.title}</td>
                <td className="hide-sm meta">
                  {f.instanceId ? <Link href={instanceHref(f.instanceId)}>{f.instanceId}</Link> : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </main>
  );
}
