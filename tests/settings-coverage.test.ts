import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { collectClaudeCode } from "@/collectors/claude-code";
import { runHeuristics } from "@/lib/heuristics";
import { runScenarios } from "@/lib/threat-scenarios";
import { makeInstance, makeServer } from "./helpers/snapshots";

// Claude Code settings coverage (vendor settings/permission-modes/MCP
// references verified 2026-10-11): controls, additional directories, sandbox
// extras, MCP approval sources with trust gating, mode semantics, and the
// heuristics that read them. Each case builds its own HOME + project.

let root: string;
let home: string;
let project: string;
const prevHome = process.env.HOME;

async function write(rel: string, data: unknown) {
  const file = path.join(root, rel);
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(data));
}
async function reset() {
  await fs.rm(home, { recursive: true, force: true });
  await fs.rm(project, { recursive: true, force: true });
  await fs.mkdir(path.join(project, ".git", "objects"), { recursive: true });
  await fs.mkdir(path.join(project, ".git", "refs"), { recursive: true });
  await fs.writeFile(path.join(project, ".git", "HEAD"), "ref: refs/heads/main\n");
}
const collect = () => collectClaudeCode([project]);
const projectInst = (r: Awaited<ReturnType<typeof collect>>) => r.instances.find((i) => i.scope === "project")!;
const userInst = (r: Awaited<ReturnType<typeof collect>>) => r.instances.find((i) => i.scope === "user")!;

beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-settings-"));
  home = path.join(root, "home");
  project = path.join(root, "project");
  process.env.HOME = home;
});
afterEach(reset);
afterAll(async () => {
  process.env.HOME = prevHome;
  await fs.rm(root, { recursive: true, force: true });
});

describe("controls, additional directories and sandbox extras", () => {
  it("collects controls from the highest-precedence file, with provenance", async () => {
    await reset();
    await write("home/.claude/settings.json", {
      skipDangerousModePermissionPrompt: true,
      permissions: { disableBypassPermissionsMode: "disable", additionalDirectories: ["~/.aws", "/srv/data"] },
      autoMode: { environment: { hosts: [] }, classifyAllShell: true },
      env: { CLAUDE_CODE_X: "1", SOME_TOKEN: "sk-fixture1234567890ABCDEF" },
    });
    await write("project/.claude/settings.local.json", { skipDangerousModePermissionPrompt: false, disableAllHooks: true });
    const r = await collect();
    const u = userInst(r);
    expect(u.controls).toEqual(
      expect.arrayContaining([
        { key: "skipDangerousModePermissionPrompt", value: "true", sourceFile: `${home}/.claude/settings.json` },
        { key: "permissions.disableBypassPermissionsMode", value: "disable", sourceFile: `${home}/.claude/settings.json` },
        { key: "autoMode.classifyAllShell", value: "true", sourceFile: `${home}/.claude/settings.json` },
      ]),
    );
    expect(u.additionalDirectories).toEqual([
      { path: "~/.aws", sourceFile: `${home}/.claude/settings.json` },
      { path: "/srv/data", sourceFile: `${home}/.claude/settings.json` },
    ]);
    expect(u.notes.some((n) => n.startsWith("autoMode configured") && n.includes("environment") && n.includes("classifyAllShell"))).toBe(true);
    expect(u.notes.some((n) => n.startsWith("env sets 2 environment variable(s)") && n.includes("SOME_TOKEN"))).toBe(true);
    expect(JSON.stringify(r)).not.toContain("sk-fixture"); // env VALUES never surface
    const p = projectInst(r);
    // local tier outranks user for the same control
    expect(p.controls.find((c) => c.key === "skipDangerousModePermissionPrompt")).toEqual({
      key: "skipDangerousModePermissionPrompt", value: "false", sourceFile: `${project}/.claude/settings.local.json`,
    });
    expect(p.controls.find((c) => c.key === "disableAllHooks")?.value).toBe("true");
    expect(p.notes.some((n) => n.startsWith("disableAllHooks: true"))).toBe(true);
  });

  it("collects sandbox extras and accepts a string allowUnsandboxedCommands", async () => {
    await reset();
    await write("home/.claude/settings.json", {
      sandbox: {
        enabled: true,
        autoAllowBashIfSandboxed: false,
        excludedCommands: ["docker compose *", `aws --token sk-fixture1234567890ABCDEF`],
        allowUnsandboxedCommands: "ask",
        filesystem: { denyRead: ["~/.ssh"], allowWrite: ["/tmp/build"] },
        network: { allowedDomains: ["github.com"], allowLocalBinding: true },
      },
    });
    const r = await collect();
    const sb = userInst(r).sandbox!;
    expect(sb.enabled).toBe(true);
    expect(sb.autoAllowBashIfSandboxed).toBe(false);
    expect(sb.excludedCommands).toHaveLength(2);
    expect(sb.excludedCommands.join(" ")).not.toContain("sk-fixture");
    expect(sb.allowUnsandboxedCommands).toBeNull();
    expect(sb.notes).toContain(`allowUnsandboxedCommands: "ask"`);
    expect(sb.notes).toContain("denyRead 1");
    expect(sb.notes).toContain("allowLocalBinding: true");
    expect(sb.fieldSources.excludedCommands).toBe(`${home}/.claude/settings.json`);
    const ids = runHeuristics({ instances: [userInst(r)], mcpServers: [] });
    expect(ids.map((f) => `${f.heuristicId}:${f.severity}`)).toContain("H6:low");
  });
});

describe("MCP approval sources (vendor: settings files + ~/.claude.json, trust-gated for project files)", () => {
  const mcpJson = { mcpServers: { docs: { command: "node", args: ["./tools/docs.js"] }, db: { command: "node", args: ["./tools/db.js"] } } };
  const byName = (r: Awaited<ReturnType<typeof collect>>) =>
    Object.fromEntries(r.mcpServers.filter((s) => s.instanceId.startsWith("claude-code:project:")).map((s) => [s.name, s.enablement]));

  it("enabledMcpjsonServers in user settings approves; disabledMcpjsonServers always wins", async () => {
    await reset();
    await write("home/.claude/settings.json", { enabledMcpjsonServers: ["docs", "db"] });
    await write("project/.claude/settings.local.json", { disabledMcpjsonServers: ["db"] });
    await write("project/.mcp.json", mcpJson);
    expect(byName(await collect())).toEqual({ docs: "enabled", db: "disabled" });
  });

  it("enableAllProjectMcpServers in the user tier approves every .mcp.json server", async () => {
    await reset();
    await write("home/.claude/settings.json", { enableAllProjectMcpServers: true });
    await write("project/.mcp.json", mcpJson);
    expect(byName(await collect())).toEqual({ docs: "enabled", db: "enabled" });
  });

  it("approvals committed to the project's own settings count only once the folder is trusted", async () => {
    await reset();
    await write("home/.claude/settings.json", {});
    await write("project/.claude/settings.json", { enableAllProjectMcpServers: true, enabledMcpjsonServers: ["db"] });
    await write("project/.mcp.json", mcpJson);
    // untrusted (no decision recorded) → ignored, stated
    let r = await collect();
    expect(byName(r)).toEqual({ docs: null, db: null });
    expect(projectInst(r).notes.filter((n) => n.includes("ignored by the vendor until this folder is trusted"))).toHaveLength(2);
    // trusted → counts
    await write("home/.claude.json", { projects: { [project]: { hasTrustDialogAccepted: true } } });
    r = await collect();
    expect(byName(r)).toEqual({ docs: "enabled", db: "enabled" });
  });

  it("the prompt choice recorded in ~/.claude.json still works, and deniedMcpServers blocks by name everywhere", async () => {
    await reset();
    await write("home/.claude/settings.json", { deniedMcpServers: [{ serverName: "db" }, { serverName: "linear" }] });
    await write("home/.claude.json", {
      mcpServers: { linear: { url: "https://mcp.linear.app/mcp" }, ok: { url: "https://ok.example/mcp" } },
      projects: { [project]: { hasTrustDialogAccepted: true, enabledMcpjsonServers: ["docs"] } },
    });
    await write("project/.mcp.json", mcpJson);
    const r = await collect();
    expect(byName(r)).toEqual({ docs: "enabled", db: "disabled" });
    const user = Object.fromEntries(r.mcpServers.filter((s) => s.instanceId === "claude-code:user").map((s) => [s.name, s.enablement]));
    expect(user).toEqual({ linear: "disabled", ok: null });
    expect(userInst(r).notes.some((n) => n.startsWith("deniedMcpServers (2)"))).toBe(true);
  });
});

describe("modes: semantics notes and H8/H9", () => {
  it("auto at the user tier → H8 low once (not repeated on project instances that inherit it)", async () => {
    await reset();
    await write("home/.claude/settings.json", { permissions: { defaultMode: "auto" }, skipDangerousModePermissionPrompt: true });
    await write("project/.claude/settings.json", { permissions: { allow: ["Bash(npm test)"] } });
    const r = await collect();
    expect(userInst(r).notes.some((n) => n.startsWith("Mode semantics") && n.includes("v2.1.283"))).toBe(true);
    const findings = runHeuristics({ instances: r.instances, mcpServers: [] });
    const h8 = findings.filter((f) => f.heuristicId === "H8");
    const h9 = findings.filter((f) => f.heuristicId === "H9");
    expect(h8).toHaveLength(1);
    expect(h8[0].instanceId).toBe("claude-code:user");
    expect(h8[0].severity).toBe("low");
    expect(h8[0].sourceFile).toBe(`${home}/.claude/settings.json`);
    expect(h9).toHaveLength(1);
    expect(h9[0].instanceId).toBe("claude-code:user");
    expect(projectInst(r).defaultMode).toBe("auto"); // still shown as the effective mode
  });

  it('"auto" in a project file is inert per the vendor: note, no H8; acceptEdits in local tier → H8 on the project', async () => {
    await reset();
    await write("home/.claude/settings.json", { permissions: { defaultMode: "default" } });
    await write("project/.claude/settings.json", { permissions: { defaultMode: "auto" } });
    let r = await collect();
    expect(projectInst(r).notes.some((n) => n.startsWith("Vendor caveat: \"auto\" set in .claude/settings.json"))).toBe(true);
    expect(runHeuristics({ instances: r.instances, mcpServers: [] }).filter((f) => f.heuristicId === "H8")).toEqual([]);

    await write("project/.claude/settings.local.json", { permissions: { defaultMode: "acceptEdits" } });
    r = await collect();
    const h8 = runHeuristics({ instances: r.instances, mcpServers: [] }).filter((f) => f.heuristicId === "H8");
    expect(h8.map((f) => f.instanceId)).toEqual([projectInst(r).id]);
    expect(h8[0].sourceFile).toBe(`${project}/.claude/settings.local.json`);
  });

  it("default, plan and dontAsk are not reduced-oversight findings; bypass stays H1 and notes the disable control", async () => {
    await reset();
    for (const mode of ["default", "plan", "dontAsk"]) {
      await write("home/.claude/settings.json", { permissions: { defaultMode: mode } });
      const r = await collect();
      const ids = runHeuristics({ instances: r.instances, mcpServers: [] }).map((f) => f.heuristicId);
      expect(ids, mode).not.toContain("H8");
      expect(ids, mode).not.toContain("H1");
    }
    await write("home/.claude/settings.json", { permissions: { defaultMode: "bypassPermissions", disableBypassPermissionsMode: "disable" } });
    const r = await collect();
    const ids = runHeuristics({ instances: r.instances, mcpServers: [] }).map((f) => f.heuristicId);
    expect(ids).toContain("H1");
    expect(ids).not.toContain("H8");
    expect(userInst(r).notes.some((n) => n.includes("disableBypassPermissionsMode") && n.includes("inert"))).toBe(true);
  });
});

describe("S5 via additionalDirectories", () => {
  it("an additional directory covering a credential store is the read atom when no Read rule exists", () => {
    const inst = makeInstance({
      defaultMode: "default",
      permissionRules: [],
      additionalDirectories: [{ path: "~/.aws", sourceFile: "/tmp/fixture/.claude/settings.json" }],
    });
    const servers = [
      makeServer({ name: "vault", envKeys: ["VAULT_TOKEN"], enablement: "enabled" }),
      makeServer({ name: "warehouse", envKeys: ["DB_PASSWORD"], enablement: "enabled" }),
    ];
    const findings = runHeuristics({ instances: [inst], mcpServers: servers });
    const s5 = runScenarios({ instances: [inst], mcpServers: servers, findings }).filter((s) => s.scenarioId === "S5-credential-concentration");
    expect(s5).toHaveLength(1);
    expect(s5[0].preconditions[2].claim).toContain("additionalDirectories");
    expect(s5[0].preconditions[2].sourceFile).toBe("/tmp/fixture/.claude/settings.json");
    const projectOnly = makeInstance({ defaultMode: "default", permissionRules: [], additionalDirectories: [{ path: "../shared-lib", sourceFile: "/tmp/x" }] });
    expect(runScenarios({ instances: [projectOnly], mcpServers: servers, findings: runHeuristics({ instances: [projectOnly], mcpServers: servers }) })).toEqual([]);
  });
});
