import type { Severity, Snapshot, ThreatScenario } from "./schema";

// Counts-only summary a user may paste anywhere. The full map of a machine's
// agent surface is recon material (SR3), so the card carries NO file paths,
// rule matchers, server names, hostnames, or machine ids — only aggregates.
// tests/share-card.test.ts asserts that against the fixture.

export const SHARE_CARD_REPO = "https://github.com/MLSecOpsHub/agentic-access-control";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function bySeverity(items: Array<{ severity: Severity }>): string {
  const parts = SEVERITIES.map((sev) => [sev, items.filter((i) => i.severity === sev).length] as const)
    .filter(([, n]) => n > 0)
    .map(([sev, n]) => `${n} ${sev}`);
  return parts.length > 0 ? parts.join(" · ") : "none";
}

export function buildShareCard(s: Snapshot, scenarios: ThreatScenario[]): string {
  const platforms = new Map<string, number>();
  for (const inst of s.instances) platforms.set(inst.platform, (platforms.get(inst.platform) ?? 0) + 1);
  const platformText = [...platforms.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([p, n]) => `${p} ×${n}`)
    .join(", ");

  const rules = s.instances.flatMap((i) => i.permissionRules);
  const count = (effect: string) => rules.filter((r) => r.effect === effect).length;
  const stdio = s.mcpServers.filter((m) => m.transport === "stdio").length;

  const byScenario = new Map<string, ThreatScenario[]>();
  for (const sc of scenarios) byScenario.set(sc.scenarioId, [...(byScenario.get(sc.scenarioId) ?? []), sc]);
  const scenarioText = [...byScenario.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([id, list]) => {
      const top = SEVERITIES.find((sev) => list.some((x) => x.severity === sev)) ?? "info";
      return `${id} ×${list.length} (${top})`;
    })
    .join(", ");

  return [
    `AgentLens posture summary · ${s.generatedAt.slice(0, 10)}`,
    `What this is: configured declarations read from local agent config files — not enforcement, not observed activity.`,
    ``,
    `Agent instances: ${s.instances.length}${platformText ? ` (${platformText})` : ""}`,
    `Permission declarations: ${rules.length} (${count("deny")} deny · ${count("ask")} ask · ${count("allow")} allow)`,
    `MCP servers: ${s.mcpServers.length} (${stdio} stdio · ${s.mcpServers.length - stdio} remote)`,
    `Risk findings: ${s.findings.length} (${bySeverity(s.findings)})`,
    `Threat scenarios: ${scenarios.length}${scenarioText ? ` (${scenarioText})` : ""}`,
    `Collectors run: ${s.collectors.join(", ")}`,
    ``,
    `Excluded on purpose: file paths, rule matchers, server names, hostnames.`,
    `— ${SHARE_CARD_REPO} (read-only, local-only)`,
  ].join("\n");
}
