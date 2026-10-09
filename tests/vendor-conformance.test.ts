import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { afterEach, describe, expect, it } from "vitest";
import { collectClaudeCode } from "@/collectors/claude-code";
import { resolveToolReachability } from "@/lib/precedence";

// Vendor-conformance fixtures (hardening Step 4): first-party Claude Code
// semantics encoded as executable expectations, so precedence regressions fail
// tests instead of external reviews. The two cases originally marked `it.fails`
// (git-root settings.local.json discovery; deny-outranks-allow across levels)
// flipped green when hardening Step 5 landed and are now locked in.
// References: Claude Code settings docs — precedence: enterprise managed >
// command line > local project > shared project > user; permission evaluation:
// deny always wins over ask/allow regardless of source level.

let roots: string[] = [];
const mkroot = async () => {
  const r = await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-conf-"));
  roots.push(r);
  return r;
};
const write = async (file: string, data: unknown) => {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, typeof data === "string" ? data : JSON.stringify(data));
};

const HOME = process.env.HOME;
afterEach(async () => {
  process.env.HOME = HOME;
  await Promise.all(roots.map((r) => fs.rm(r, { recursive: true, force: true })));
  roots = [];
});

async function fixtureHome(settings: unknown): Promise<string> {
  const home = await mkroot();
  await write(path.join(home, ".claude", "settings.json"), settings);
  process.env.HOME = home;
  return home;
}

describe("tier precedence for single-value settings (defaultMode)", () => {
  it("project settings override user settings", async () => {
    await fixtureHome({ permissions: { defaultMode: "acceptEdits" } });
    const project = await mkroot();
    await write(path.join(project, ".claude", "settings.json"), {
      permissions: { defaultMode: "plan" },
    });
    const { instances } = await collectClaudeCode([project]);
    const proj = instances.find((i) => i.scope === "project");
    expect(proj?.defaultMode).toBe("plan");
    expect(instances.find((i) => i.scope === "user")?.defaultMode).toBe("acceptEdits");
  });

  it("local project settings override shared project settings", async () => {
    await fixtureHome({ permissions: { defaultMode: "acceptEdits" } });
    const project = await mkroot();
    await write(path.join(project, ".claude", "settings.json"), {
      permissions: { defaultMode: "plan" },
    });
    await write(path.join(project, ".claude", "settings.local.json"), {
      permissions: { defaultMode: "bypassPermissions" },
    });
    const { instances } = await collectClaudeCode([project]);
    expect(instances.find((i) => i.scope === "project")?.defaultMode).toBe("bypassPermissions");
  });
});

describe("settings file discovery", () => {
  it("settings.local.json at the scanned project root is collected", async () => {
    await fixtureHome({});
    const project = await mkroot();
    await write(path.join(project, ".claude", "settings.local.json"), {
      permissions: { allow: ["Bash(local-canary)"] },
    });
    const { instances } = await collectClaudeCode([project]);
    const rules = instances.find((i) => i.scope === "project")?.permissionRules ?? [];
    expect(rules.some((r) => r.matcher === "Bash(local-canary)" && r.sourceLevel === "local")).toBe(true);
  });

  // Vendor semantics: project settings live at the GIT ROOT — running from a
  // nested package directory still applies <gitRoot>/.claude/settings.local.json.
  it("settings.local.json is found at the git root when scanning a nested directory", async () => {
    await fixtureHome({});
    const repo = await mkroot();
    await fs.mkdir(path.join(repo, ".git"), { recursive: true });
    await write(path.join(repo, ".claude", "settings.local.json"), {
      permissions: { allow: ["Bash(git-root-canary)"] },
    });
    const nested = path.join(repo, "packages", "app");
    await fs.mkdir(nested, { recursive: true });

    const { instances } = await collectClaudeCode([nested]);
    const rules = instances.flatMap((i) => i.permissionRules);
    expect(rules.some((r) => r.matcher === "Bash(git-root-canary)")).toBe(true);
  });
});

describe("permission evaluation order", () => {
  // Vendor semantics: deny always wins — a user-level deny beats a
  // project-level allow for the same matcher (effect-first precedenceRank).
  it("a deny outranks an allow for the same matcher regardless of level", async () => {
    await fixtureHome({ permissions: { deny: ["WebFetch"] } });
    const project = await mkroot();
    await write(path.join(project, ".claude", "settings.json"), {
      permissions: { allow: ["WebFetch"] },
    });
    const { instances } = await collectClaudeCode([project]);
    const rules = instances.find((i) => i.scope === "project")?.permissionRules ?? [];
    const allWebFetchRules = rules.filter((r) => r.matcher === "WebFetch");
    expect(allWebFetchRules.length).toBe(2);
    // Scenario engine reuse: resolveToolReachability must agree with the deny-first semantics
    const result = resolveToolReachability(allWebFetchRules, "WebFetch");
    expect(result?.effect).toBe("deny");
  });
});

describe("project root deduplication", () => {
  it("scanning the git root and a nested directory yields one project instance", async () => {
    await fixtureHome({});
    const repo = await mkroot();
    await fs.mkdir(path.join(repo, ".git"), { recursive: true });
    await write(path.join(repo, ".claude", "settings.json"), {
      permissions: { allow: ["Bash(npm test)"] },
    });
    const nested = path.join(repo, "packages", "app");
    await fs.mkdir(nested, { recursive: true });

    const { instances } = await collectClaudeCode([repo, nested]);
    expect(instances.filter((i) => i.scope === "project").length).toBe(1);
  });
});

describe("per-field single-value merging across tiers", () => {
  it("defaultMode carries the source file that contributed it", async () => {
    await fixtureHome({ permissions: { defaultMode: "acceptEdits" } });
    const project = await mkroot();
    const localFile = path.join(project, ".claude", "settings.local.json");
    await write(localFile, { permissions: { defaultMode: "plan" } });
    const { instances } = await collectClaudeCode([project]);
    const proj = instances.find((i) => i.scope === "project");
    expect(proj?.defaultMode).toBe("plan");
    expect(proj?.defaultModeSourceFile).toBe(localFile);
  });

  it("sandbox fields merge per-field: each field from the highest tier defining it", async () => {
    const home = await fixtureHome({ sandbox: { allowUnsandboxedCommands: true } });
    const project = await mkroot();
    const projFile = path.join(project, ".claude", "settings.json");
    await write(projFile, { sandbox: { enabled: false } });

    const { instances } = await collectClaudeCode([project]);
    const sb = instances.find((i) => i.scope === "project")?.sandbox;
    expect(sb?.enabled).toBe(false); // from project tier
    expect(sb?.allowUnsandboxedCommands).toBe(true); // from user tier
    expect(sb?.fieldSources.enabled).toBe(projFile);
    expect(sb?.fieldSources.allowUnsandboxedCommands).toBe(
      path.join(home, ".claude", "settings.json"),
    );
  });
});

describe("per-project ~/.claude.json entries", () => {
  it("project-scoped MCP servers in ~/.claude.json attach to the project instance", async () => {
    const home = await fixtureHome({});
    const project = await mkroot();
    await write(path.join(project, ".claude", "settings.json"), {});
    await write(path.join(home, ".claude.json"), {
      projects: {
        [project]: { mcpServers: { perProj: { command: "node", args: ["srv.js"] } } },
      },
    });

    const { instances, mcpServers } = await collectClaudeCode([project]);
    const inst = instances.find((i) => i.scope === "project");
    const srv = mcpServers.find((s) => s.name === "perProj");
    expect(srv?.instanceId).toBe(inst?.id);
    expect(srv?.sourceFile).toBe(path.join(home, ".claude.json"));
    expect(inst?.configFiles).toContain(path.join(home, ".claude.json"));
  });

  it("a ~/.claude.json project entry alone is enough to surface a project instance", async () => {
    const home = await fixtureHome({});
    const project = await mkroot(); // no .claude/, no .mcp.json
    await write(path.join(home, ".claude.json"), {
      projects: { [project]: { mcpServers: { only: { command: "node" } } } },
    });
    const { instances } = await collectClaudeCode([project]);
    expect(instances.some((i) => i.scope === "project")).toBe(true);
  });

  it("enabled/disabled lists set enablement on .mcp.json servers; disabled wins", async () => {
    const home = await fixtureHome({});
    const project = await mkroot();
    await write(path.join(project, ".mcp.json"), {
      mcpServers: {
        approved: { command: "node" },
        rejected: { command: "node" },
        undecided: { command: "node" },
        contested: { command: "node" },
      },
    });
    await write(path.join(home, ".claude.json"), {
      projects: {
        [project]: {
          enabledMcpjsonServers: ["approved", "contested"],
          disabledMcpjsonServers: ["rejected", "contested"],
        },
      },
    });

    const { mcpServers } = await collectClaudeCode([project]);
    const byName = new Map(mcpServers.map((s) => [s.name, s.enablement]));
    expect(byName.get("approved")).toBe("enabled");
    expect(byName.get("rejected")).toBe("disabled");
    expect(byName.get("undecided")).toBe(null);
    expect(byName.get("contested")).toBe("disabled"); // conservative on conflict
  });
});

describe("MCP declaration provenance", () => {
  it("~/.claude.json servers attach to the user instance; .mcp.json to the project instance", async () => {
    const home = await fixtureHome({});
    await write(path.join(home, ".claude.json"), {
      mcpServers: { userSrv: { command: "npx", args: ["user-server"] } },
    });
    const project = await mkroot();
    await write(path.join(project, ".mcp.json"), {
      mcpServers: { projSrv: { url: "https://mcp.example.com", env: { API_KEY: "value-dropped" } } },
    });
    const { instances, mcpServers } = await collectClaudeCode([project]);

    const userSrv = mcpServers.find((s) => s.name === "userSrv");
    const projSrv = mcpServers.find((s) => s.name === "projSrv");
    expect(userSrv?.instanceId).toBe("claude-code:user");
    expect(projSrv?.instanceId).toBe(instances.find((i) => i.scope === "project")?.id);
    expect(projSrv?.transport).toBe("http");
    expect(projSrv?.envKeys).toEqual(["API_KEY"]);
    expect(JSON.stringify(mcpServers)).not.toContain("value-dropped");
  });
});
