import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { afterEach, describe, expect, it } from "vitest";
import { collectClaudeCode } from "@/collectors/claude-code";

// Vendor-conformance fixtures (hardening Step 4): first-party Claude Code
// semantics encoded as executable expectations, so precedence regressions fail
// tests instead of external reviews. Two cases are marked `it.fails` — they
// encode DOCUMENTED vendor behavior the collector does not implement yet
// (hardening Step 5). When Step 5 lands, vitest flags them as "expected to
// fail but passed": remove the `.fails` marker to lock the behavior in.
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
  // Collector gap tracked as hardening Step 5 ("settings.local.json git-root
  // loading"). Remove `.fails` when Step 5 lands.
  it.fails("settings.local.json is found at the git root when scanning a nested directory", async () => {
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
  // project-level allow for the same matcher. The collector's precedenceRank
  // is level-first, which orders the allow ahead of the deny. Step 5
  // reimplements rule merging per documented semantics; remove `.fails` then.
  it.fails("a deny outranks an allow for the same matcher regardless of level", async () => {
    await fixtureHome({ permissions: { deny: ["WebFetch"] } });
    const project = await mkroot();
    await write(path.join(project, ".claude", "settings.json"), {
      permissions: { allow: ["WebFetch"] },
    });
    const { instances } = await collectClaudeCode([project]);
    const rules = (instances.find((i) => i.scope === "project")?.permissionRules ?? [])
      .filter((r) => r.matcher === "WebFetch")
      .sort((a, b) => a.precedenceRank - b.precedenceRank);
    expect(rules.length).toBe(2);
    expect(rules[0].effect).toBe("deny");
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
