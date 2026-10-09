import type {
  AgentInstance,
  McpServer,
  RiskFinding,
  Precondition,
  SeveranceHint,
  Severity,
  ThreatScenario,
} from "./schema";
import { resolveToolReachability, shellToolFor } from "./precedence";

export const SCENARIO_CAVEAT =
  "These are configured declarations composed by AgentLens, not observed enforcement or an observed attack. The platform's own evaluator is ground truth (SR4).";

const SEVERITY_LADDER: Severity[] = ["critical", "high", "medium", "low", "info"];
function downgradeOneLevel(sev: Severity): Severity {
  const i = SEVERITY_LADDER.indexOf(sev);
  return SEVERITY_LADDER[Math.min(i + 1, SEVERITY_LADDER.length - 1)];
}

interface ScenarioCtx {
  mcpServers: McpServer[];
  findings: RiskFinding[];
}

interface CatalogEntry {
  scenarioId: string;
  evaluate(inst: AgentInstance, ctx: ScenarioCtx): ThreatScenario | null;
}

const S1: CatalogEntry = {
  scenarioId: "S1-supply-chain-to-exfil",
  evaluate(inst, ctx) {
    const servers = ctx.mcpServers
      .filter((s) => s.instanceId === inst.id && s.enablement !== "disabled")
      .sort((a, b) => a.name.localeCompare(b.name)); // determinism

    // Atom A: H3-high finding (unpinned stdio runner) tied to a specific,
    // non-disabled server. Match by sourceFile + name-in-title.
    const entryServer = servers.find((s) =>
      ctx.findings.some(
        (f) =>
          f.heuristicId === "H3" &&
          f.instanceId === inst.id &&
          f.severity === "high" &&
          f.sourceFile === s.sourceFile &&
          f.title.includes(`"${s.name}"`),
      ),
    );
    if (!entryServer) return null;

    // Atom B: H4 finding (credential env keys) on ANY non-disabled server for
    // the instance — spec explicitly says "on any server", need not be entryServer.
    const credServer = servers.find((s) =>
      ctx.findings.some(
        (f) =>
          f.heuristicId === "H4" &&
          f.instanceId === inst.id &&
          f.sourceFile === s.sourceFile &&
          f.title.includes(`"${s.name}"`),
      ),
    );
    if (!credServer) return null;

    // Atom C: effective allow Bash (via precedence helper) OR sandbox hole (H6
    // finding — reuse, don't recompute inst.sandbox booleans by hand).
    const shellTool = shellToolFor(inst.platform);
    const bashReach = shellTool ? resolveToolReachability(inst.permissionRules, shellTool) : null;
    const bashAllows = bashReach?.effect === "allow";
    const h6 = ctx.findings.find(
      (f) => f.heuristicId === "H6" && f.instanceId === inst.id,
    );
    if (!bashAllows && !h6) return null;

    const anyNullEnablement =
      entryServer.enablement === null || credServer.enablement === null;

    // Build preconditions in order.
    const preconditions: Precondition[] = [];
    const h3Finding = ctx.findings.find(
      (f) =>
        f.heuristicId === "H3" &&
        f.instanceId === inst.id &&
        f.severity === "high" &&
        f.sourceFile === entryServer.sourceFile &&
        f.title.includes(`"${entryServer.name}"`),
    );
    preconditions.push({
      kind: "mcp-server",
      claim: `MCP server "${entryServer.name}" is launched via unpinned package runner${
        entryServer.enablement === null ? ", with no recorded approval choice" : ""
      }`,
      evidence: h3Finding?.evidence || "",
      sourceFile: h3Finding?.sourceFile || null,
      refId: h3Finding?.id || null,
      confidence: "declared",
    });

    const h4Finding = ctx.findings.find(
      (f) =>
        f.heuristicId === "H4" &&
        f.instanceId === inst.id &&
        f.sourceFile === credServer.sourceFile &&
        f.title.includes(`"${credServer.name}"`),
    );
    preconditions.push({
      kind: "mcp-server",
      claim: `MCP server "${credServer.name}" is configured with credential environment keys${
        credServer.enablement === null ? ", with no recorded approval choice" : ""
      }`,
      evidence: h4Finding?.evidence || "",
      sourceFile: h4Finding?.sourceFile || null,
      refId: h4Finding?.id || null,
      confidence: "declared",
    });

    if (bashAllows && bashReach) {
      preconditions.push({
        kind: "permission-rule",
        claim: `"${bashReach.rule.matcher}" at ${bashReach.rule.sourceLevel} tier is reachable before any deny for the ${shellTool} tool`,
        evidence: `${bashReach.rule.effect} ${bashReach.rule.matcher} (${bashReach.rule.sourceLevel})`,
        sourceFile: bashReach.rule.sourceFile,
        refId: ctx.findings.find(
          (f) =>
            f.heuristicId === "H2" &&
            f.instanceId === inst.id &&
            f.sourceFile === bashReach.rule.sourceFile,
        )?.id || null,
        confidence: "declared",
      });
    } else {
      preconditions.push({
        kind: "sandbox-field",
        claim: h6?.title || "Sandbox is disabled or escapable",
        evidence: h6?.evidence || "",
        sourceFile: h6?.sourceFile || null,
        refId: h6?.id || null,
        confidence: "declared",
      });
    }

    const severanceHints: SeveranceHint[] = preconditions.map((_, i) => ({
      preconditionIndex: i,
      text: `Removing the configuration element at the file above severs this path.`,
    }));

    const severity = anyNullEnablement ? downgradeOneLevel("critical") : "critical";

    return {
      id: `S1-supply-chain-to-exfil:${inst.id}:0`,
      scenarioId: "S1-supply-chain-to-exfil",
      title: `Configured declarations permit a path: unpinned MCP server → shell access → credential env (${inst.id})`,
      severity,
      confidence: "declared",
      preconditions,
      categories: { owaspAsi: ["ASI02", "ASI03", "ASI10"], stride: ["E", "I"] },
      severanceHints,
      instanceId: inst.id,
      caveat: SCENARIO_CAVEAT,
    };
  },
};

const S2: CatalogEntry = {
  scenarioId: "S2-gating-collapse",
  evaluate(inst, ctx) {
    const h1 = ctx.findings.find(
      (f) => f.heuristicId === "H1" && f.instanceId === inst.id,
    );
    if (!h1) return null;

    const hook = inst.hooks.length > 0 ? inst.hooks[0] : null;
    const server = ctx.mcpServers
      .filter((s) => s.instanceId === inst.id && s.enablement !== "disabled")
      .sort((a, b) => a.name.localeCompare(b.name))[0];

    if (!hook && !server) return null;

    const nullEnablement = !hook && server?.enablement === null;
    const preconditions: Precondition[] = [];

    preconditions.push({
      kind: "mode",
      claim: h1.title,
      evidence: h1.evidence,
      sourceFile: h1.sourceFile,
      refId: h1.id,
      confidence: "declared",
    });

    if (hook) {
      preconditions.push({
        kind: "hook",
        claim: `Hook on "${hook.event}" event pipes content to shell${
          hook.matcher ? ` (matcher: ${hook.matcher})` : ""
        }`,
        evidence: hook.commandPreview,
        sourceFile: hook.sourceFile,
        refId:
          ctx.findings.find(
            (f) =>
              f.heuristicId === "H7" &&
              f.instanceId === inst.id &&
              f.sourceFile === hook.sourceFile,
          )?.id || null,
        confidence: "declared",
      });
    } else if (server) {
      preconditions.push({
        kind: "mcp-server",
        claim: `MCP server "${server.name}" is present for this instance${
          server.enablement === null ? " with no recorded approval choice" : ""
        }`,
        evidence: `MCP server: ${server.name}`,
        sourceFile: server.sourceFile,
        refId: null,
        confidence: "declared",
      });
    }

    const severanceHints: SeveranceHint[] = preconditions.map((_, i) => ({
      preconditionIndex: i,
      text: `Removing the configuration element at the file above severs this path.`,
    }));

    const severity = nullEnablement ? downgradeOneLevel("critical") : "critical";

    return {
      id: `S2-gating-collapse:${inst.id}:0`,
      scenarioId: "S2-gating-collapse",
      title: `Configured declarations permit a path: bypassed gating → MCP/hook surface (${inst.id})`,
      severity,
      confidence: "declared",
      preconditions,
      categories: { owaspAsi: ["ASI03", "ASI05"], stride: ["E"] },
      severanceHints,
      instanceId: inst.id,
      caveat: SCENARIO_CAVEAT,
    };
  },
};

export const CATALOG: CatalogEntry[] = [S1, S2];
