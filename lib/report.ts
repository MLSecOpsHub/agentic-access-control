import type { RiskFinding, Severity, Snapshot, ThreatScenario } from "./schema";
import { SCENARIO_CAVEAT } from "./scenario-catalog";

// Machine-readable output for `agentlens check` (headless / CI): a JSON report
// and SARIF 2.1.0. Both are built from the same redacted snapshot the dashboard
// renders (SR2) and go to stdout only — no new data path (SR3). Every emitted
// text carries the SR4 caveat; the wording contract applies unchanged.

export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_RANK[severity] <= SEVERITY_RANK[threshold];
}

export function worstSeverity(findings: RiskFinding[], scenarios: ThreatScenario[]): Severity | null {
  const all = [...findings.map((f) => f.severity), ...scenarios.map((s) => s.severity)];
  if (all.length === 0) return null;
  return all.sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b])[0];
}

export const REPORT_CAVEAT =
  "AgentLens reports configured declarations read from local agent configuration files — not enforcement, not observed activity, not an observed attack. The platform's own evaluator is ground truth (SR4).";

// Rule catalogue for SARIF: heuristics (docs/collectors.md §6) and scenarios
// (docs/threat-scenarios.md §5). Descriptions name conditions, never outcomes.
const RULES: Record<string, { name: string; description: string; help: string }> = {
  H1: { name: "bypass-mode", description: "Permission gating bypassed by the configured default mode", help: "docs/collectors.md#6-risk-heuristics-v1" },
  H2: { name: "wildcard-allow", description: "Unbounded allow rule on a shell, write or edit tool", help: "docs/collectors.md#6-risk-heuristics-v1" },
  H3: { name: "remote-package-runner", description: "stdio MCP server launched via a remote package runner (npx -y, uvx, pipx run)", help: "docs/collectors.md#6-risk-heuristics-v1" },
  H4: { name: "credential-env", description: "MCP server configured with credential-shaped environment keys (values never collected)", help: "docs/collectors.md#6-risk-heuristics-v1" },
  H5: { name: "retired", description: "Retired heuristic kept for old snapshots", help: "docs/collectors.md#6-risk-heuristics-v1" },
  H6: { name: "sandbox-off", description: "Sandbox disabled or escapable where the platform offers one", help: "docs/collectors.md#6-risk-heuristics-v1" },
  H7: { name: "hook-pipes-remote-to-shell", description: "Hook command pipes remote content to a shell", help: "docs/collectors.md#6-risk-heuristics-v1" },
  PARSE: { name: "config-not-readable", description: "A configuration file could not be fully read (fixed error code, no content echoed)", help: "docs/collectors.md#1-shared-collector-contract" },
  "S1-supply-chain-to-exfil": { name: "scenario-supply-chain-to-exfil", description: "Configured path: unpinned MCP server → shell access → credential env", help: "docs/threat-scenarios.md#5-initial-catalog-v1" },
  "S2-gating-collapse": { name: "scenario-gating-collapse", description: "Configured path: bypassed gating → MCP/hook surface", help: "docs/threat-scenarios.md#5-initial-catalog-v1" },
  "S3-hook-injection-chain": { name: "scenario-hook-injection-chain", description: "Configured path: remote-content hook → shell/write access → unsandboxed execution", help: "docs/threat-scenarios.md#5-initial-catalog-v1" },
  "S4-unreviewed-project-takeover": { name: "scenario-unreviewed-project-takeover", description: "Configured path: team-writable allow on a shell/write tool → project MCP server with no recorded approval", help: "docs/threat-scenarios.md#5-initial-catalog-v1" },
  "S5-credential-concentration": { name: "scenario-credential-concentration", description: "Configured path: read access over home/config paths → multiple credential-bearing MCP server configs", help: "docs/threat-scenarios.md#5-initial-catalog-v1" },
};

const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export interface ReportSummary {
  instances: number;
  platforms: Record<string, number>;
  permissionRules: number;
  mcpServers: number;
  findings: Record<Severity, number>;
  scenarios: Record<Severity, number>;
  worstSeverity: Severity | null;
}

export function summarize(snapshot: Snapshot, scenarios: ThreatScenario[]): ReportSummary {
  const bySev = (items: Array<{ severity: Severity }>) =>
    (Object.keys(SEVERITY_RANK) as Severity[]).reduce(
      (acc, sev) => ({ ...acc, [sev]: items.filter((i) => i.severity === sev).length }),
      {} as Record<Severity, number>,
    );
  const platforms: Record<string, number> = {};
  for (const i of snapshot.instances) platforms[i.platform] = (platforms[i.platform] ?? 0) + 1;
  return {
    instances: snapshot.instances.length,
    platforms,
    permissionRules: snapshot.instances.reduce((n, i) => n + i.permissionRules.length, 0),
    mcpServers: snapshot.mcpServers.length,
    findings: bySev(snapshot.findings),
    scenarios: bySev(scenarios),
    worstSeverity: worstSeverity(snapshot.findings, scenarios),
  };
}

export function buildJsonReport(snapshot: Snapshot, scenarios: ThreatScenario[], version: string) {
  return {
    tool: { name: "AgentLens", version },
    caveat: REPORT_CAVEAT,
    summary: summarize(snapshot, scenarios),
    snapshot,
    scenarios,
  };
}

function artifactUri(file: string): string {
  // Absolute paths become file URIs; fixture-style "~/..." stays a plain string.
  return file.startsWith("/") ? `file://${encodeURI(file)}` : file;
}

const location = (file: string | null) =>
  file ? [{ physicalLocation: { artifactLocation: { uri: artifactUri(file) } } }] : [];

export function buildSarif(snapshot: Snapshot, scenarios: ThreatScenario[], version: string) {
  const usedRuleIds = new Set<string>([
    ...snapshot.findings.map((f) => f.heuristicId as string),
    ...scenarios.map((s) => s.scenarioId),
  ]);
  const rules = [...usedRuleIds].sort().map((id) => {
    const r = RULES[id] ?? { name: id, description: id, help: "docs/" };
    return {
      id,
      name: r.name,
      shortDescription: { text: r.description },
      fullDescription: { text: `${r.description}. ${REPORT_CAVEAT}` },
      helpUri: `https://github.com/MLSecOpsHub/agentic-access-control/blob/main/${r.help}`,
    };
  });
  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));

  const findingResults = snapshot.findings.map((f) => ({
    ruleId: f.heuristicId,
    ruleIndex: ruleIndex.get(f.heuristicId),
    level: SARIF_LEVEL[f.severity],
    message: { text: `${f.title}. Evidence: ${f.evidence}` },
    locations: location(f.sourceFile),
    partialFingerprints: { agentlensId: f.id },
    properties: { severity: f.severity, instanceId: f.instanceId, kind: "finding" },
  }));

  const scenarioResults = scenarios.map((s) => ({
    ruleId: s.scenarioId,
    ruleIndex: ruleIndex.get(s.scenarioId),
    level: SARIF_LEVEL[s.severity],
    message: { text: `${s.title}. ${s.caveat}` },
    locations: s.preconditions.flatMap((p) => location(p.sourceFile)),
    partialFingerprints: { agentlensId: s.id },
    properties: {
      severity: s.severity,
      instanceId: s.instanceId,
      kind: "scenario",
      confidence: s.confidence,
      owaspAsi: s.categories.owaspAsi,
      stride: s.categories.stride,
      preconditions: s.preconditions.map((p) => ({ kind: p.kind, claim: p.claim, sourceFile: p.sourceFile, refId: p.refId })),
      severanceHints: s.severanceHints.map((h) => h.text),
    },
  }));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "AgentLens",
            version,
            informationUri: "https://github.com/MLSecOpsHub/agentic-access-control",
            fullDescription: { text: REPORT_CAVEAT },
            rules,
          },
        },
        automationDetails: { id: `agentlens/${snapshot.generatedAt}` },
        invocations: [{ executionSuccessful: true, endTimeUtc: snapshot.generatedAt }],
        properties: {
          caveat: REPORT_CAVEAT,
          scenarioCaveat: SCENARIO_CAVEAT,
          schemaVersion: snapshot.schemaVersion,
          snapshotHash: snapshot.hash,
          collectors: snapshot.collectors,
          summary: summarize(snapshot, scenarios),
        },
        results: [...findingResults, ...scenarioResults],
      },
    ],
  };
}
