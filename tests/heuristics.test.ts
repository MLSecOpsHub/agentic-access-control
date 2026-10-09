import { describe, expect, it } from "vitest";
import { runHeuristics } from "@/lib/heuristics";
import type { AgentInstance } from "@/lib/schema";
import { makeServer, makeInstance as makeInstanceHelper } from "./helpers/snapshots";

// Hardening Step 5 heuristic fixes: H3 no longer flags pinned package specs
// with the unpinned claim text (review probe P2), and H1/H6 findings attribute
// the file that actually contributed the value, not configFiles[0] (F6).

const run = (ctx: Partial<Parameters<typeof runHeuristics>[0]>) =>
  runHeuristics({ instances: [], mcpServers: [], ...ctx });

function makeInstance(overrides: Partial<AgentInstance> = {}): AgentInstance {
  const inst = makeInstanceHelper(overrides);
  return {
    ...inst,
    id: "claude-code:project:deadbeef",
    scope: "project",
    projectPath: "/tmp/fixture/project",
    configFiles: [
      "/tmp/fixture/home/.claude/settings.json",
      "/tmp/fixture/project/.claude/settings.local.json",
    ],
    defaultMode: null,
    defaultModeSourceFile: null,
    permissionRules: [],
    sandbox: null,
    hooks: [],
    ...overrides,
  };
}

describe("H3 — remote package runners", () => {
  it("unpinned npx -y is high severity with the latest-upstream claim", () => {
    const findings = run({
      mcpServers: [makeServer({ commandOrUrl: "npx", args: ["-y", "@scope/server"] })],
    }).filter((f) => f.heuristicId === "H3");
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].evidence).toContain("executes latest upstream");
  });

  it("pinned npx -y spec is the lower-severity variant without the latest-upstream claim", () => {
    const findings = run({
      mcpServers: [makeServer({ commandOrUrl: "npx", args: ["-y", "@scope/server@1.2.3"] })],
    }).filter((f) => f.heuristicId === "H3");
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("medium");
    expect(findings[0].title).toContain("version pinned");
    expect(findings[0].evidence).not.toContain("executes latest upstream");
  });

  it("pip-style uvx pkg==1.2 counts as pinned", () => {
    const findings = run({
      mcpServers: [makeServer({ commandOrUrl: "uvx", args: ["some-server==1.2"] })],
    }).filter((f) => f.heuristicId === "H3");
    expect(findings[0]?.severity).toBe("medium");
  });
});

describe("H1/H6 — true source-file attribution", () => {
  it("H1 cites the file that contributed defaultMode, not configFiles[0]", () => {
    const findings = run({
      instances: [
        makeInstance({
          defaultMode: "bypassPermissions",
          defaultModeSourceFile: "/tmp/fixture/project/.claude/settings.local.json",
        }),
      ],
    }).filter((f) => f.heuristicId === "H1");
    expect(findings.length).toBe(1);
    expect(findings[0].sourceFile).toBe("/tmp/fixture/project/.claude/settings.local.json");
  });

  it("H6 cites the per-field sandbox source from the collector merge", () => {
    const findings = run({
      instances: [
        makeInstance({
          sandbox: {
            enabled: false,
            allowUnsandboxedCommands: null,
            networkAllowlist: [],
            notes: null,
            fieldSources: { enabled: "/tmp/fixture/project/.claude/settings.json" },
          },
        }),
      ],
    }).filter((f) => f.heuristicId === "H6");
    expect(findings.length).toBe(1);
    expect(findings[0].sourceFile).toBe("/tmp/fixture/project/.claude/settings.json");
  });
});
