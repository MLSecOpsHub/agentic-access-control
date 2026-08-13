import Link from "next/link";
import { notFound } from "next/navigation";
import { loadDashboardData } from "@/lib/snapshot";
import { shortPath } from "@/lib/format";
import { EffectBadge, ModeBadge, SeverityBadge, SnapshotMeta, sortFindings } from "../../components";

export const dynamic = "force-dynamic";
export const metadata = { title: "Agent instance" };

export default async function AgentDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id: rawId } = await params;
  const id = decodeURIComponent(rawId);
  const { current } = await loadDashboardData();
  const s = current.snapshot;

  const inst = s.instances.find((i) => i.id === id);
  if (!inst) notFound();

  // Display grouping only (deny, ask, allow) — deliberately NOT an
  // evaluation-order claim; see local/mvp-review-accuracy-analysis.md (F1).
  const effectOrder = { deny: 0, ask: 1, allow: 2 } as const;
  const rules = [...inst.permissionRules].sort(
    (a, b) =>
      effectOrder[a.effect] - effectOrder[b.effect] ||
      a.sourceLevel.localeCompare(b.sourceLevel) ||
      a.matcher.localeCompare(b.matcher),
  );
  const servers = s.mcpServers.filter((m) => m.instanceId === inst.id);
  const findings = sortFindings(s.findings.filter((f) => f.instanceId === inst.id));

  return (
    <main>
      <p className="meta">
        <Link href="/">← Overview</Link>
      </p>
      <h1>
        {inst.platform} <span className="pill">{inst.scope}</span>
      </h1>
      <p className="meta">
        {inst.projectPath ? <>project <code>{shortPath(inst.projectPath)}</code> · </> : null}
        id <code>{inst.id}</code>
        {inst.version ? <> · version {inst.version}</> : null}
        {inst.defaultMode ? <> · mode <ModeBadge mode={inst.defaultMode} /></> : null}
      </p>
      <SnapshotMeta current={current} />

      <h2>Configured permission declarations ({rules.length})</h2>
      <p className="meta">
        Declarations merged from all settings tiers, grouped by effect for display with per-rule
        provenance. This table does not claim evaluation order — the platform&apos;s own evaluator
        is ground truth (SR4: verify against the source file).
      </p>
      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th>Effect</th>
              <th>Matcher</th>
              <th className="hide-sm">Level</th>
              <th className="hide-sm">Source file</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r, i) => (
              <tr key={i}>
                <td><EffectBadge effect={r.effect} /></td>
                <td><code>{r.matcher}</code></td>
                <td className="hide-sm"><span className="pill">{r.sourceLevel}</span></td>
                <td className="hide-sm meta">{shortPath(r.sourceFile)}</td>
              </tr>
            ))}
            {rules.length === 0 && (
              <tr>
                <td colSpan={4} className="meta">
                  No explicit rules — the platform&apos;s defaults apply.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <h2>Sandbox</h2>
      {inst.sandbox ? (
        <div
          className={
            inst.sandbox.enabled === false || inst.sandbox.allowUnsandboxedCommands === true
              ? "notice notice-warn"
              : "notice"
          }
        >
          enabled: <code>{String(inst.sandbox.enabled)}</code> · allowUnsandboxedCommands:{" "}
          <code>{String(inst.sandbox.allowUnsandboxedCommands)}</code>
          {inst.sandbox.networkAllowlist.length > 0 && (
            <> · egress allowlist: {inst.sandbox.networkAllowlist.map((h, i) => (
              <code key={i}>{h}</code>
            ))}</>
          )}
          {inst.sandbox.notes && <div className="meta">{inst.sandbox.notes}</div>}
        </div>
      ) : (
        <p className="meta">No sandbox configuration found for this instance.</p>
      )}

      <h2>Hooks ({inst.hooks.length})</h2>
      {inst.hooks.length > 0 ? (
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                <th>Event</th>
                <th>Matcher</th>
                <th>Command (redacted preview)</th>
                <th className="hide-sm">Source file</th>
              </tr>
            </thead>
            <tbody>
              {inst.hooks.map((h, i) => (
                <tr key={i}>
                  <td>{h.event}</td>
                  <td>{h.matcher ? <code>{h.matcher}</code> : <span className="meta">any</span>}</td>
                  <td><code>{h.commandPreview}</code></td>
                  <td className="hide-sm meta">{shortPath(h.sourceFile)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="meta">None.</p>
      )}

      <h2>MCP servers ({servers.length})</h2>
      {servers.length > 0 ? (
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Transport</th>
                <th>Command / URL</th>
                <th className="hide-sm">Env keys (values redacted)</th>
              </tr>
            </thead>
            <tbody>
              {servers.map((m, i) => (
                <tr key={i}>
                  <td><b>{m.name}</b></td>
                  <td><span className="pill">{m.transport}</span></td>
                  <td><code>{[m.commandOrUrl, ...m.args].join(" ")}</code></td>
                  <td className="hide-sm meta">{m.envKeys.length > 0 ? m.envKeys.join(", ") : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="meta">None declared by this instance&apos;s config files.</p>
      )}

      <h2>Findings ({findings.length})</h2>
      {findings.length > 0 ? (
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Finding</th>
                <th className="hide-sm">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id}>
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td>{f.title}</td>
                  <td className="hide-sm"><code>{f.evidence}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="meta">None for this instance.</p>
      )}
    </main>
  );
}
