import type {
  AgentInstance,
  McpServer,
  PermissionRule,
  RiskFinding,
  Precondition,
  SeveranceHint,
  Severity,
  ThreatScenario,
} from "./schema";
import { readToolFor, resolveToolReachability, shellToolFor, writeToolFor } from "./precedence";

export const SCENARIO_CAVEAT =
  "These are configured declarations composed by AgentLens, not observed enforcement or an observed attack. The platform's own evaluator is ground truth (SR4).";

// Wording contract (docs/threat-scenarios.md §7): never reachable in a title,
// claim, hint, or rendered page. Asserted in tests on emitted objects AND HTML.
export const SCENARIO_BANNED_PHRASES = [
  "attack is possible",
  "vulnerable to",
  "exploitable",
  "attacker can",
  "will execute",
];

// First tool in `tools` for which an unbounded allow wins under deny-first
// precedence (Step 5 semantics via resolveToolReachability).
function reachableAllow(
  inst: AgentInstance,
  tools: Array<string | null>,
): { tool: string; rule: PermissionRule } | null {
  for (const tool of tools) {
    if (!tool) continue;
    const r = resolveToolReachability(inst.permissionRules, tool);
    if (r?.effect === "allow") return { tool, rule: r.rule };
  }
  return null;
}

const SEVERITY_LADDER: Severity[] = ["critical", "high", "medium", "low", "info"];
function downgradeOneLevel(sev: Severity): Severity {
  const i = SEVERITY_LADDER.indexOf(sev);
  return SEVERITY_LADDER[Math.min(i + 1, SEVERITY_LADDER.length - 1)];
}

// Observed MCP usage from session traces (docs/session-trace.md §13): which
// declared server names were called, in how many sessions, from which cwds.
// Invocation matching only — never which rule permitted the call.
export interface ObservedMcpUsage {
  sessions: Set<string>;
  cwds: Set<string>;
  lastAt: string;
}
export interface ObservedUsage {
  mcpServersUsed: Map<string, ObservedMcpUsage>;
  windowDays: number;
}

interface ScenarioCtx {
  mcpServers: McpServer[];
  findings: RiskFinding[];
  observed?: ObservedUsage;
}

const SEVERITY_UP: Record<Severity, Severity> = { info: "low", low: "medium", medium: "high", high: "critical", critical: "critical" };

// Upgrade to declared+observed when the scenario's entry server was used in a
// traced session belonging to this instance (cwd under projectPath; any cwd
// for user scope). Raises one level per §5; appends an observed atom.
function applyObservedUsage(scenario: ThreatScenario, serverName: string, inst: AgentInstance, ctx: ScenarioCtx): ThreatScenario {
  const usage = ctx.observed?.mcpServersUsed.get(serverName);
  if (!usage) return scenario;
  const prefix = inst.projectPath ? inst.projectPath.replace(/\/$/, "") + "/" : null;
  const relevant = prefix === null || [...usage.cwds].some((c) => c === inst.projectPath || c.startsWith(prefix));
  if (!relevant) return scenario;
  const n = usage.sessions.size;
  const sessionId = [...usage.sessions][0];
  return {
    ...scenario,
    confidence: "declared+observed",
    severity: SEVERITY_UP[scenario.severity],
    preconditions: [
      ...scenario.preconditions,
      {
        kind: "observed-event",
        claim: `MCP server "${serverName}" was used in ${n} traced session${n === 1 ? "" : "s"} in the last ${ctx.observed!.windowDays} days (invocation matching from session traces — never which rule permitted it)`,
        evidence: `last used ${usage.lastAt}`,
        sourceFile: null,
        refId: `trace:${sessionId}`,
        confidence: "observed",
      },
    ],
  };
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

    return applyObservedUsage({
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
    }, entryServer.name, inst, ctx);
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

const S3: CatalogEntry = {
  scenarioId: "S3-hook-injection-chain",
  evaluate(inst, ctx) {
    const h7 = ctx.findings.find((f) => f.heuristicId === "H7" && f.instanceId === inst.id);
    if (!h7) return null;
    const h6 = ctx.findings.find((f) => f.heuristicId === "H6" && f.instanceId === inst.id);
    if (!h6) return null;
    const reach = reachableAllow(inst, [shellToolFor(inst.platform), writeToolFor(inst.platform)]);
    if (!reach) return null;

    const preconditions: Precondition[] = [
      {
        kind: "hook",
        claim: `A hook pipes remote content to a shell inside the agent loop (${h7.title})`,
        evidence: h7.evidence,
        sourceFile: h7.sourceFile,
        refId: h7.id,
        confidence: "declared",
      },
      {
        kind: "permission-rule",
        claim: `"${reach.rule.matcher}" at ${reach.rule.sourceLevel} tier is reachable before any deny for the ${reach.tool} tool`,
        evidence: `${reach.rule.effect} ${reach.rule.matcher} (${reach.rule.sourceLevel})`,
        sourceFile: reach.rule.sourceFile,
        refId:
          ctx.findings.find(
            (f) => f.heuristicId === "H2" && f.instanceId === inst.id && f.sourceFile === reach.rule.sourceFile,
          )?.id || null,
        confidence: "declared",
      },
      {
        kind: "sandbox-field",
        claim: h6.title,
        evidence: h6.evidence,
        sourceFile: h6.sourceFile,
        refId: h6.id,
        confidence: "declared",
      },
    ];
    const severanceHints: SeveranceHint[] = preconditions.map((_, i) => ({
      preconditionIndex: i,
      text: `Removing the configuration element at the file above severs this path.`,
    }));
    return {
      id: `S3-hook-injection-chain:${inst.id}:0`,
      scenarioId: "S3-hook-injection-chain",
      title: `Configured declarations permit a path: remote-content hook → ${reach.tool} access → unsandboxed execution (${inst.id})`,
      severity: "high",
      confidence: "declared",
      preconditions,
      categories: { owaspAsi: ["ASI02", "ASI05"], stride: ["T", "E"] },
      severanceHints,
      instanceId: inst.id,
      caveat: SCENARIO_CAVEAT,
    };
  },
};

const TEAM_WRITABLE_TIERS = new Set(["project", "local"]);

const S4: CatalogEntry = {
  scenarioId: "S4-unreviewed-project-takeover",
  evaluate(inst, ctx) {
    if (!inst.projectPath) return null;
    const tools = [shellToolFor(inst.platform), writeToolFor(inst.platform)].filter(
      (t): t is string => t !== null,
    );
    const candidates = inst.permissionRules
      .filter(
        (r) =>
          r.effect === "allow" &&
          TEAM_WRITABLE_TIERS.has(r.sourceLevel) &&
          r.tool !== null &&
          tools.includes(r.tool),
      )
      .sort((a, b) => a.precedenceRank - b.precedenceRank || a.matcher.localeCompare(b.matcher));
    // Deny-first: an unbounded deny for the tool anywhere outranks every allow for it.
    const rule = candidates.find(
      (r) => resolveToolReachability(inst.permissionRules, r.tool!)?.effect !== "deny",
    );
    if (!rule) return null;

    const projectPrefix = inst.projectPath + "/";
    const server = ctx.mcpServers
      .filter(
        (s) => s.instanceId === inst.id && s.enablement === null && s.sourceFile.startsWith(projectPrefix),
      )
      .sort((a, b) => a.name.localeCompare(b.name))[0];
    if (!server) return null;

    const tierText =
      rule.sourceLevel === "project" ? "project-shared (checked-in)" : "per-checkout local";
    const preconditions: Precondition[] = [
      {
        kind: "permission-rule",
        claim: `"${rule.matcher}" is allowed at ${rule.sourceLevel} tier — ${tierText} configuration — and no unbounded deny for ${rule.tool} outranks it`,
        evidence: `${rule.effect} ${rule.matcher} (${rule.sourceLevel})`,
        sourceFile: rule.sourceFile,
        refId:
          ctx.findings.find(
            (f) => f.heuristicId === "H2" && f.instanceId === inst.id && f.sourceFile === rule.sourceFile,
          )?.id || null,
        confidence: "declared",
      },
      {
        kind: "mcp-server",
        claim: `MCP server "${server.name}" is declared in project-shared configuration with no recorded approval choice`,
        evidence: `MCP server: ${server.name} (${server.transport})`,
        sourceFile: server.sourceFile,
        refId:
          ctx.findings.find(
            (f) =>
              f.heuristicId === "H3" &&
              f.instanceId === inst.id &&
              f.sourceFile === server.sourceFile &&
              f.title.includes(`"${server.name}"`),
          )?.id || null,
        confidence: "declared",
      },
    ];
    const severanceHints: SeveranceHint[] = preconditions.map((_, i) => ({
      preconditionIndex: i,
      text: `Removing the configuration element at the file above severs this path.`,
    }));
    return applyObservedUsage({
      id: `S4-unreviewed-project-takeover:${inst.id}:0`,
      scenarioId: "S4-unreviewed-project-takeover",
      title: `Configured declarations permit a path: ${tierText} allow on ${rule.tool} → project MCP server with no recorded approval (${inst.id})`,
      // Base high, and the §5 null-enablement cap does not apply: the missing
      // approval choice IS this scenario's atom, not an uncertainty about it.
      severity: "high",
      confidence: "declared",
      preconditions,
      categories: { owaspAsi: ["ASI03", "ASI05"], stride: ["S", "E"] },
      severanceHints,
      instanceId: inst.id,
      caveat: SCENARIO_CAVEAT,
    }, server.name, inst, ctx);
  },
};

// A read-tool matcher that reaches beyond the project: home, dotfile and
// credential-store paths where agent configs (and their env blocks) live.
export const HOME_OR_CONFIG_PATH = /(~|\$HOME|\/home\/|\/Users\/|\/root\/|\.ssh|\.aws|\.gnupg|\.config|\.env\b|\.claude|\.gemini|\.codex|\.mcp\.json)/;

const S5: CatalogEntry = {
  scenarioId: "S5-credential-concentration",
  evaluate(inst, ctx) {
    const h4For = (s: McpServer) =>
      ctx.findings.find(
        (f) =>
          f.heuristicId === "H4" &&
          f.instanceId === inst.id &&
          f.sourceFile === s.sourceFile &&
          f.title.includes(`"${s.name}"`),
      );
    const credServers = ctx.mcpServers
      .filter((s) => s.instanceId === inst.id && s.enablement !== "disabled" && h4For(s))
      .sort((a, b) => a.name.localeCompare(b.name));
    if (credServers.length < 2) return null;

    const readTool = readToolFor(inst.platform);
    if (!readTool) return null;
    const reach = resolveToolReachability(inst.permissionRules, readTool);
    let rule: PermissionRule | null = null;
    if (reach?.effect === "allow") rule = reach.rule;
    else if (reach?.effect !== "deny") {
      rule =
        inst.permissionRules
          .filter((r) => r.effect === "allow" && r.tool === readTool && HOME_OR_CONFIG_PATH.test(r.matcher))
          .sort((a, b) => a.precedenceRank - b.precedenceRank || a.matcher.localeCompare(b.matcher))[0] ?? null;
    }
    // Claude Code: permissions.additionalDirectories grants file access outside
    // the project without prompts — the same atom, declared differently.
    const extraDir =
      !rule && reach?.effect !== "deny"
        ? [...inst.additionalDirectories].sort((a, b) => a.path.localeCompare(b.path)).find((d) => HOME_OR_CONFIG_PATH.test(d.path)) ?? null
        : null;
    if (!rule && !extraDir) return null;

    const preconditions: Precondition[] = credServers.slice(0, 2).map((s) => {
      const h4 = h4For(s)!;
      return {
        kind: "mcp-server" as const,
        claim: `MCP server "${s.name}" is configured with credential environment keys${
          s.enablement === null ? ", with no recorded approval choice" : ""
        }`,
        evidence: h4.evidence,
        sourceFile: h4.sourceFile,
        refId: h4.id,
        confidence: "declared" as const,
      };
    });
    if (rule) {
      preconditions.push({
        kind: "permission-rule",
        claim: `"${rule.matcher}" allows ${readTool} over home or config paths and no unbounded deny for ${readTool} outranks it`,
        evidence: `${rule.effect} ${rule.matcher} (${rule.sourceLevel})`,
        sourceFile: rule.sourceFile,
        refId:
          ctx.findings.find(
            (f) => f.heuristicId === "H2" && f.instanceId === inst.id && f.sourceFile === rule.sourceFile,
          )?.id || null,
        confidence: "declared",
      });
    } else if (extraDir) {
      preconditions.push({
        kind: "permission-rule",
        claim: `permissions.additionalDirectories grants ${readTool} access to "${extraDir.path}" outside the project without approval, and no unbounded deny for ${readTool} outranks it`,
        evidence: `additionalDirectories: ${extraDir.path}`,
        sourceFile: extraDir.sourceFile,
        refId: null,
        confidence: "declared",
      });
    }
    const severanceHints: SeveranceHint[] = preconditions.map((_, i) => ({
      preconditionIndex: i,
      text: `Removing the configuration element at the file above severs this path.`,
    }));
    const anyNull = credServers.slice(0, 2).some((s) => s.enablement === null);
    return {
      id: `S5-credential-concentration:${inst.id}:0`,
      scenarioId: "S5-credential-concentration",
      title: `Configured declarations permit a path: ${readTool} over home/config paths → ${credServers.length} credential-bearing MCP server configs (${inst.id})`,
      severity: anyNull ? downgradeOneLevel("medium") : "medium",
      confidence: "declared",
      preconditions,
      categories: { owaspAsi: ["ASI03"], stride: ["I"] },
      severanceHints,
      instanceId: inst.id,
      caveat: SCENARIO_CAVEAT,
    };
  },
};

export const CATALOG: CatalogEntry[] = [S1, S2, S3, S4, S5];
