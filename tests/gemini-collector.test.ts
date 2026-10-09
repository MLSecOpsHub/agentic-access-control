import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { collectGeminiCli } from "@/collectors/gemini-cli";
import { runHeuristics } from "@/lib/heuristics";
import type { CollectorResult } from "@/collectors/claude-code";
import { buildMachine, rmMachine, SECRETS, type Machine } from "./helpers/machine";

// Gemini CLI collector against the shared fixture machine (docs/collectors.md §4).
// Mapping under test: tools.allowed → allow, tools.exclude → deny, tools.core →
// note only, general.defaultApprovalMode → defaultMode, tools.sandbox →
// SandboxConfig, mcp.excluded → enablement, trust: true → note, hooks shape.

describe("Gemini CLI collector", () => {
  let m: Machine;
  let r: CollectorResult;
  const prevHome = process.env.HOME;

  beforeAll(async () => {
    m = await buildMachine();
    process.env.HOME = m.home;
    r = await collectGeminiCli([m.project, m.projectBad]);
  });
  afterAll(async () => {
    process.env.HOME = prevHome;
    await rmMachine(m);
  });

  it("produces a user instance and one project instance (project-bad has no .gemini)", () => {
    expect(r.issues).toEqual([]);
    expect(r.instances.map((i) => i.scope).sort()).toEqual(["project", "user"]);
    const user = r.instances.find((i) => i.scope === "user")!;
    expect(user.id).toBe("gemini-cli:user");
    expect(user.platform).toBe("gemini-cli");
    const project = r.instances.find((i) => i.scope === "project")!;
    expect(project.projectPath).toBe(m.project);
    expect(project.configFiles).toContain(`${m.project}/.gemini/settings.json`);
  });

  it("maps tools.allowed → allow and tools.exclude → deny, deny ranked first", () => {
    const user = r.instances.find((i) => i.scope === "user")!;
    const rows = user.permissionRules.map((p) => `${p.effect} ${p.matcher}`).sort();
    expect(rows).toEqual(["allow run_shell_command", "allow run_shell_command(git)", "deny write_file"]);
    expect(user.permissionRules.find((p) => p.matcher === "run_shell_command(git)")?.tool).toBe("run_shell_command");
    const sorted = [...user.permissionRules].sort((a, b) => a.precedenceRank - b.precedenceRank);
    expect(sorted[0].effect).toBe("deny");
  });

  it("project instance merges tiers: project allow write_file coexists with user deny write_file", () => {
    const project = r.instances.find((i) => i.scope === "project")!;
    const wf = project.permissionRules.filter((p) => p.matcher === "write_file");
    expect(wf.map((p) => `${p.effect}@${p.sourceLevel}`).sort()).toEqual(["allow@project", "deny@user"]);
    expect(project.defaultMode).toBe("auto_edit"); // inherited from the user tier
  });

  it("defaultApprovalMode, sandbox and hooks are collected with provenance", () => {
    const user = r.instances.find((i) => i.scope === "user")!;
    expect(user.defaultMode).toBe("auto_edit");
    expect(user.defaultModeSourceFile).toBe(`${m.home}/.gemini/settings.json`);
    expect(user.sandbox?.enabled).toBe(false);
    expect(user.sandbox?.fieldSources.enabled).toBe(`${m.home}/.gemini/settings.json`);
    expect(user.sandbox?.notes).toContain("network access: true");
    expect(user.hooks).toHaveLength(1);
    expect(user.hooks[0].event).toBe("BeforeTool");
    expect(user.hooks[0].commandPreview).not.toContain(SECRETS.aws);
  });

  it("MCP servers: transports, enablement from mcp.excluded, secrets never persisted", () => {
    const user = r.mcpServers.filter((s) => s.instanceId === "gemini-cli:user");
    const byName = Object.fromEntries(user.map((s) => [s.name, s]));
    expect(byName.gh.transport).toBe("stdio");
    expect(byName.gh.envKeys).toEqual(["GITHUB_TOKEN"]);
    expect(byName.gh.enablement).toBeNull();
    expect(byName.remote.transport).toBe("http");
    expect(byName.remote.commandOrUrl).not.toContain(SECRETS.keyedValue);
    expect(byName.legacy.transport).toBe("sse");
    expect(byName.legacy.enablement).toBe("disabled");
    const text = JSON.stringify(r);
    for (const v of Object.values(SECRETS)) expect(text).not.toContain(v);
    const project = r.mcpServers.filter((s) => s.instanceId.startsWith("gemini-cli:project:"));
    expect(project.map((s) => s.name)).toEqual(["db"]);
    expect(project[0].envKeys).toEqual(["PGPASSWORD"]);
  });

  it("records mapping notes: tools.core, trusted server, folder trust, uncollected inputs", () => {
    const user = r.instances.find((i) => i.scope === "user")!;
    const project = r.instances.find((i) => i.scope === "project")!;
    expect(user.notes.some((n) => n.startsWith("tools.core"))).toBe(true);
    expect(user.notes.some((n) => n.includes('"gh"') && n.includes("trust: true"))).toBe(true);
    expect(project.notes.some((n) => n.startsWith("Folder trust is enabled"))).toBe(true);
    expect(user.notes.some((n) => n.includes("TOML policy files"))).toBe(true);
  });

  it("heuristics fire on the Gemini vocabulary: H2 bare run_shell_command, H3 npx -y, H4 env, H6, H7", () => {
    const ids = new Set(runHeuristics(r).map((f) => f.heuristicId));
    expect([...ids].sort()).toEqual(["H2", "H3", "H4", "H6", "H7"]);
  });
});
