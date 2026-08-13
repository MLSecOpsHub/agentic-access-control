import Link from "next/link";
import { loadDashboardData } from "@/lib/snapshot";
import { shortPath } from "@/lib/format";
import { SeverityBadge, SnapshotMeta, instanceHref, sortFindings } from "../components";

export const dynamic = "force-dynamic";
export const metadata = { title: "Findings" };

export default async function Findings() {
  const { current } = await loadDashboardData();
  const findings = sortFindings(current.snapshot.findings);

  return (
    <main>
      <h1>Risk findings ({findings.length})</h1>
      <SnapshotMeta current={current} />
      <p className="meta">
        Heuristics H1–H7 are documented in <code>docs/collectors.md</code> §6; PARSE entries mean a
        config could not be fully read, so coverage there is incomplete. Evidence is shown
        post-redaction (SR2).
      </p>
      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Rule</th>
              <th>Finding</th>
              <th className="hide-sm">Evidence</th>
              <th className="hide-sm">Instance / file</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td><span className="pill">{f.heuristicId}</span></td>
                <td>{f.title}</td>
                <td className="hide-sm"><code>{f.evidence}</code></td>
                <td className="hide-sm meta">
                  {f.instanceId ? <Link href={instanceHref(f.instanceId)}>{f.instanceId}</Link> : "—"}
                  {f.sourceFile ? <div>{shortPath(f.sourceFile)}</div> : null}
                </td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr><td colSpan={5} className="meta">No findings — posture is clean under H1–H7.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </main>
  );
}
