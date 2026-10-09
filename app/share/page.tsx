import { loadDashboardData } from "@/lib/snapshot";
import { runScenarios } from "@/lib/threat-scenarios";
import { buildShareCard } from "@/lib/share-card";
import { SnapshotMeta } from "../components";
import { CopyCard } from "./copy-card";

export const dynamic = "force-dynamic";
export const metadata = { title: "Share card" };

export default async function Share() {
  const { current } = await loadDashboardData();
  const s = current.snapshot;
  const text = buildShareCard(
    s,
    runScenarios({ instances: s.instances, mcpServers: s.mcpServers, findings: s.findings }),
  );

  return (
    <main>
      <h1>Share card</h1>
      <SnapshotMeta current={current} />
      <p className="meta">
        A counts-only summary you can paste into a post or a ticket. It deliberately carries no
        file paths, rule matchers, server names, hostnames or machine ids — the full map of this
        machine&apos;s agent surface is recon material and stays local (SR3). Copying is a local
        clipboard action you trigger; AgentLens sends nothing anywhere.
      </p>
      <CopyCard text={text} />
    </main>
  );
}
