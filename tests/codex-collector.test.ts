import { promises as fs } from "fs";
import path from "path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { collectCodexCli } from "@/collectors/codex-cli";
import { runHeuristics } from "@/lib/heuristics";
import type { CollectorResult } from "@/collectors/claude-code";
import { buildMachine, rmMachine, SECRETS, type Machine } from "./helpers/machine";

// Codex CLI collector against the shared fixture machine (docs/collectors.md §3).

describe("Codex CLI collector", () => {
  let m: Machine;
  let r: CollectorResult;
  const prevHome = process.env.HOME;
  const prevCodexHome = process.env.CODEX_HOME;

  beforeAll(async () => {
    m = await buildMachine();
    process.env.HOME = m.home;
    delete process.env.CODEX_HOME;
    r = await collectCodexCli([m.project, m.projectBad]);
  });
  afterAll(async () => {
    process.env.HOME = prevHome;
    if (prevCodexHome !== undefined) process.env.CODEX_HOME = prevCodexHome;
    await rmMachine(m);
  });

  it("produces a user instance and a trusted project instance, no issues", () => {
    expect(r.issues).toEqual([]);
    expect(r.instances.map((i) => i.scope).sort()).toEqual(["project", "user"]);
    expect(r.instances.every((i) => i.permissionRules.length === 0)).toBe(true); // no per-tool list in Codex config
  });

  it("maps approval never + danger-full-access to a bypass mode (H1) and a disabled sandbox (H6)", () => {
    const user = r.instances.find((i) => i.scope === "user")!;
    expect(user.defaultMode).toMatch(/^bypass/);
    expect(user.defaultModeSourceFile).toBe(`${m.home}/.codex/config.toml`);
    expect(user.sandbox?.enabled).toBe(false);
    expect(user.sandbox?.notes).toContain("sandbox_mode: danger-full-access");
    const ids = runHeuristics({ instances: [user], mcpServers: r.mcpServers.filter((s) => s.instanceId === user.id) }).map((f) => f.heuristicId);
    expect(ids).toContain("H1");
    expect(ids).toContain("H6");
  });

  it("a trusted project overrides sandbox_mode but inherits approval_policy, with provenance", () => {
    const project = r.instances.find((i) => i.scope === "project")!;
    expect(project.projectPath).toBe(m.project);
    expect(project.sandbox?.enabled).toBe(true);
    expect(project.sandbox?.fieldSources.enabled).toBe(`${m.project}/.codex/config.toml`);
    expect(project.sandbox?.notes).toContain("network_access: true");
    expect(project.defaultMode).toBe("never"); // not bypass: sandbox is workspace-write here
    expect(project.notes.some((n) => n.startsWith("Project trust: trusted"))).toBe(true);
    expect(project.notes.some((n) => n.includes("approval_policy never") && n.includes("only remaining gate"))).toBe(true);
  });

  it("MCP servers: transports, key names from env/bearer_token_env_var, enabled=false → disabled, no secrets", () => {
    const user = Object.fromEntries(r.mcpServers.filter((s) => s.instanceId === "codex-cli:user").map((s) => [s.name, s]));
    expect(user.github.transport).toBe("stdio");
    expect(user.github.envKeys).toEqual(["GITHUB_TOKEN"]);
    expect(user.github.enablement).toBeNull();
    expect(user.remote.transport).toBe("http");
    expect(user.remote.envKeys).toEqual(["REMOTE_API_TOKEN"]);
    expect(user.remote.enablement).toBe("disabled");
    expect(user.remote.commandOrUrl).not.toContain(SECRETS.keyedValue);
    const project = r.mcpServers.filter((s) => s.instanceId.startsWith("codex-cli:project:"));
    expect(project.map((s) => s.name)).toEqual(["db"]);
    const text = JSON.stringify(r);
    for (const v of Object.values(SECRETS)) expect(text, v).not.toContain(v);
  });

  it("records mapping notes: gates, shell env policy, web_search, uncollected inputs", () => {
    const user = r.instances.find((i) => i.scope === "user")!;
    expect(user.notes[0]).toContain("no per-tool allow/ask/deny list");
    expect(user.notes.some((n) => n.includes("shell_environment_policy") && n.includes("inherit = all"))).toBe(true);
    expect(user.notes.some((n) => n.startsWith("web_search = live"))).toBe(true);
    expect(user.notes.some((n) => n.includes("requirements.toml"))).toBe(true);
  });

  it("an untrusted project is listed but its values are not merged; malformed TOML yields a fixed code only", async () => {
    await fs.writeFile(
      path.join(m.home, ".codex", "config.toml"),
      [`approval_policy = "on-request"`, `sandbox_mode = "read-only"`, `[projects."${m.project}"]`, `trust_level = "untrusted"`, ``].join("\n"),
    );
    const { instances } = await collectCodexCli([m.project]);
    const project = instances.find((i) => i.scope === "project")!;
    expect(project.sandbox?.notes).toContain("sandbox_mode: read-only"); // user value, project not merged
    expect(project.defaultMode).toBe("on-request");
    expect(project.notes.some((n) => n.startsWith("Project trust: untrusted"))).toBe(true);

    await fs.writeFile(path.join(m.home, ".codex", "config.toml"), `approval_policy = "never\n[broken ${SECRETS.openai}`);
    const bad = await collectCodexCli([]);
    expect(bad.issues).toEqual([{ file: `${m.home}/.codex/config.toml`, code: "ERR_TOML_SYNTAX" }]);
    expect(JSON.stringify(bad)).not.toContain(SECRETS.openai);
  });
});
