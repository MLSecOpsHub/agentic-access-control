import { loadDashboardData } from "@/lib/snapshot";
import { runScenarios } from "@/lib/threat-scenarios";
import { SnapshotMeta, ScenarioList, sortScenarios } from "../components";

export const dynamic = "force-dynamic";
export const metadata = { title: "Threat scenarios" };

export default async function ThreatModel() {
  const { current } = await loadDashboardData();
  const s = current.snapshot;
  const scenarios = sortScenarios(
    runScenarios({ instances: s.instances, mcpServers: s.mcpServers, findings: s.findings }),
  );

  return (
    <main>
      <h1>Threat scenarios ({scenarios.length})</h1>
      <SnapshotMeta current={current} />
      <p className="meta">
        Catalog: <code>docs/threat-scenarios.md</code> §5 (v1 covers S1, S2 only).
      </p>
      {scenarios.length === 0 ? (
        <p className="meta">No scenario from the current catalog matches the collected data.</p>
      ) : (
        <ScenarioList scenarios={scenarios} />
      )}
    </main>
  );
}
