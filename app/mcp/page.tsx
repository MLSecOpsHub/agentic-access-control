import Link from "next/link";
import { loadDashboardData } from "@/lib/snapshot";
import { shortPath } from "@/lib/format";
import { SnapshotMeta, instanceHref } from "../components";

export const dynamic = "force-dynamic";
export const metadata = { title: "MCP servers" };

export default async function McpInventory() {
  const { current } = await loadDashboardData();
  const s = current.snapshot;

  return (
    <main>
      <h1>MCP servers ({s.mcpServers.length})</h1>
      <SnapshotMeta current={current} />
      <p className="meta">
        Env values are dropped at collection time (SR2) — key names remain so credential-bearing
        servers stay visible. Tool lists appear only when statically declared; AgentLens never
        executes a server to enumerate them (SR1).
      </p>
      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Transport</th>
              <th>Command / URL</th>
              <th className="hide-sm">Env keys</th>
              <th className="hide-sm">Declared tools</th>
              <th>Instance</th>
              <th className="hide-sm">Source</th>
            </tr>
          </thead>
          <tbody>
            {s.mcpServers.map((m, i) => (
              <tr key={i}>
                <td><b>{m.name}</b></td>
                <td><span className="pill">{m.transport}</span></td>
                <td><code>{[m.commandOrUrl, ...m.args].join(" ")}</code></td>
                <td className="hide-sm meta">{m.envKeys.length > 0 ? m.envKeys.join(", ") : "—"}</td>
                <td className="hide-sm meta">{m.declaredTools ? m.declaredTools.join(", ") : "not declared"}</td>
                <td className="meta"><Link href={instanceHref(m.instanceId)}>{m.instanceId}</Link></td>
                <td className="hide-sm meta">{shortPath(m.sourceFile)}</td>
              </tr>
            ))}
            {s.mcpServers.length === 0 && (
              <tr><td colSpan={7} className="meta">No MCP servers found in any scanned config.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </main>
  );
}
