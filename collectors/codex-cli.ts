import { promises as fs } from "fs";
import os from "os";
import path from "path";
import type { AgentInstance, McpServer, SandboxConfig, SourceLevel } from "../lib/schema";
import { redact } from "../lib/redact";
import { asStringArray, hash8, readTomlConfig, type ParseIssue } from "./util";
import type { CollectorResult } from "./claude-code";

// Codex CLI collector — spec: docs/collectors.md §3. Vendor docs verified
// 2026-10-11 (Codex configuration reference and sample config.toml):
//   - Files: $CODEX_HOME/config.toml (default ~/.codex/config.toml) and a
//     project-scoped <dir>/.codex/config.toml that is loaded ONLY when the
//     user config records `[projects."<dir>"] trust_level = "trusted"`.
//     Profile files ($CODEX_HOME/<name>.config.toml) apply only via --profile
//     (flag tier) and requirements.toml / cloud-managed policies constrain
//     from above — both are declared, not read.
//   - Gates: `approval_policy` (on-request | never | granular table;
//     on-failure deprecated, untrusted unsupported) and `sandbox_mode`
//     (read-only | workspace-write | danger-full-access) with
//     `[sandbox_workspace_write] network_access / writable_roots`.
//     `never` + `danger-full-access` is the vendor's bypass combination.
//   - `[mcp_servers.<name>]`: stdio (command/args/env/cwd) or HTTP (url,
//     bearer_token_env_var, http_headers, env_http_headers); `enabled`,
//     enabled_tools/disabled_tools, default_tools_approval_mode.
//   - No per-tool allow/ask/deny list exists in config.toml: permissionRules
//     stay empty and the instance notes say why (SR4). Execution-policy rules
//     are not collected.

const codexHome = () =>
  process.env.CODEX_HOME ? path.resolve(process.env.CODEX_HOME) : path.join(os.homedir(), ".codex");

interface SettingsFile {
  file: string;
  level: SourceLevel;
  data: Record<string, unknown>;
}

// Project (when trusted) overrides user for single-value settings.
const LEVEL_RANK: Record<string, number> = { project: 0, user: 1 };

const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const table = (v: unknown): Record<string, unknown> | null =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

function approvalPolicyOf(data: Record<string, unknown>): string | null {
  const v = data.approval_policy;
  if (typeof v === "string") return v;
  if (table(v) && "granular" in (v as object)) return "granular";
  return null;
}

function firstDefined<T>(files: SettingsFile[], pick: (d: Record<string, unknown>) => T | null) {
  for (const sf of files) {
    const v = pick(sf.data);
    if (v !== null) return { value: v, file: sf.file };
  }
  return null;
}

function modeFrom(files: SettingsFile[]): { value: string | null; sourceFile: string | null } {
  const approval = firstDefined(files, approvalPolicyOf);
  const sandbox = firstDefined(files, (d) => str(d.sandbox_mode));
  if (approval?.value === "never" && sandbox?.value === "danger-full-access") {
    return {
      value: "bypass (approval_policy never + sandbox_mode danger-full-access)",
      sourceFile: approval.file,
    };
  }
  return approval ? { value: redact(approval.value), sourceFile: approval.file } : { value: null, sourceFile: null };
}

function sandboxFrom(files: SettingsFile[]): SandboxConfig | null {
  const mode = firstDefined(files, (d) => str(d.sandbox_mode));
  if (!mode) return null;
  const ww = firstDefined(files, (d) => table(d.sandbox_workspace_write));
  const network = ww ? ww.value.network_access : undefined;
  const roots = ww ? asStringArray(ww.value.writable_roots) : [];
  const fieldSources: Record<string, string> = { enabled: mode.file };
  if (ww) fieldSources.networkAccess = ww.file;
  return {
    enabled: mode.value !== "danger-full-access",
    allowUnsandboxedCommands: null,
    networkAllowlist: [],
    autoAllowBashIfSandboxed: null,
    excludedCommands: [],
    notes: [
      `sandbox_mode: ${redact(mode.value)}`,
      `workspace-write network_access: ${typeof network === "boolean" ? network : "unset"}`,
      roots.length > 0 ? `additional writable_roots: ${roots.length}` : null,
      "danger-full-access disables the sandbox entirely (vendor docs)",
    ]
      .filter((x): x is string => x !== null)
      .join("; "),
    fieldSources,
  };
}

function mcpServersFrom(data: Record<string, unknown>, sourceFile: string, instanceId: string): McpServer[] {
  const block = table(data.mcp_servers);
  if (!block) return [];
  const out: McpServer[] = [];
  for (const [name, cfgRaw] of Object.entries(block)) {
    const cfg = table(cfgRaw);
    if (!cfg) continue;
    const url = str(cfg.url);
    const command = str(cfg.command);
    // Key NAMES only (SR2): env keys, the env var holding the bearer token, and
    // the env vars that feed env_http_headers. http_headers values are never read.
    const envKeys = new Set<string>(Object.keys(table(cfg.env) ?? {}));
    const bearer = str(cfg.bearer_token_env_var);
    if (bearer) envKeys.add(bearer);
    for (const v of Object.values(table(cfg.env_http_headers) ?? {})) if (typeof v === "string") envKeys.add(v);
    out.push({
      name: redact(name),
      transport: url ? "http" : command ? "stdio" : "unknown",
      commandOrUrl: redact(url ?? command ?? ""),
      args: asStringArray(cfg.args).map(redact),
      envKeys: [...envKeys],
      declaredTools: null,
      enablement: cfg.enabled === false ? "disabled" : cfg.enabled === true ? "enabled" : null,
      sourceFile,
      instanceId,
    });
  }
  return out;
}

function serverNotes(sf: SettingsFile): string[] {
  const notes: string[] = [];
  for (const [name, cfgRaw] of Object.entries(table(sf.data.mcp_servers) ?? {})) {
    const cfg = table(cfgRaw);
    if (!cfg) continue;
    const mode = str(cfg.default_tools_approval_mode);
    if (mode) notes.push(`MCP server "${redact(name)}" in ${sf.file}: default_tools_approval_mode = ${redact(mode)}.`);
    const allow = asStringArray(cfg.enabled_tools);
    const deny = asStringArray(cfg.disabled_tools);
    if (allow.length > 0 || deny.length > 0) {
      notes.push(
        `MCP server "${redact(name)}" in ${sf.file}: tool filter — enabled_tools ${allow.length}, disabled_tools ${deny.length} (server-side filter, not an approval grant).`,
      );
    }
  }
  return notes;
}

async function profileFileCount(): Promise<number> {
  try {
    return (await fs.readdir(codexHome())).filter((f) => f.endsWith(".config.toml")).length;
  } catch {
    return 0;
  }
}

function notesFrom(
  files: SettingsFile[],
  scope: "user" | "project",
  trust: { level: string | null; file: string | null; projectFile: string | null },
  profiles: number,
): string[] {
  const notes: string[] = [];
  const approval = firstDefined(files, approvalPolicyOf);
  const sandbox = firstDefined(files, (d) => str(d.sandbox_mode));
  notes.push(
    `Codex CLI has no per-tool allow/ask/deny list in config.toml: approval_policy (${approval ? redact(approval.value) : "unset → vendor default"}) and sandbox_mode (${sandbox ? redact(sandbox.value) : "unset → vendor default read-only"}) are the gates. Execution-policy rules and requirements.toml / managed policies are not collected.`,
  );
  if (approval?.value === "never" && sandbox?.value !== "danger-full-access") {
    notes.push(`approval_policy never (${approval.file}): no approval prompts — the sandbox is the only remaining gate.`);
  }
  if (approval?.value === "granular") {
    notes.push(`approval_policy is a granular table (${approval.file}) — per-category flags are not interpreted; read the file.`);
  }
  const shell = firstDefined(files, (d) => table(d.shell_environment_policy));
  if (shell) {
    const inherit = str(shell.value.inherit);
    const setKeys = Object.keys(table(shell.value.set) ?? {});
    notes.push(
      `shell_environment_policy in ${shell.file}: inherit = ${inherit ? redact(inherit) : "unset"}${setKeys.length > 0 ? `; ${setKeys.length} explicit env override(s) (names only: ${setKeys.map(redact).join(", ")})` : ""}.`,
    );
  }
  const web = firstDefined(files, (d) => str(d.web_search));
  if (web && web.value !== "disabled") notes.push(`web_search = ${redact(web.value)} (${web.file}).`);
  for (const sf of files) notes.push(...serverNotes(sf));
  if (profiles > 0) {
    notes.push(`${profiles} profile file(s) (*.config.toml) present in ${codexHome()} — applied only when selected with --profile (flag tier); not merged.`);
  }
  if (scope === "project") {
    if (trust.level === "trusted") {
      notes.push(`Project trust: trusted (trust_level in ${trust.file}) — the project-scoped ${trust.projectFile} is loaded and overrides user settings above.`);
    } else if (trust.level === "untrusted") {
      notes.push(`Project trust: untrusted (trust_level in ${trust.file}) — Codex does not load ${trust.projectFile}; its values are listed as declared but inactive.`);
    } else {
      notes.push(`Project trust: no recorded trust_level for this directory in the user config — Codex loads ${trust.projectFile} only after trust is granted; read project-tier values as conditional.`);
    }
  }
  return notes;
}

export async function collectCodexCli(projectRoots: string[]): Promise<CollectorResult> {
  const issues: ParseIssue[] = [];
  const instances: AgentInstance[] = [];
  const mcpServers: McpServer[] = [];
  const userFile = path.join(codexHome(), "config.toml");
  const userData = await readTomlConfig(userFile, issues);
  const userSettings: SettingsFile[] = userData ? [{ file: userFile, level: "user", data: userData }] : [];
  const profiles = userData ? await profileFileCount() : 0;

  if (userData) {
    const id = "codex-cli:user";
    const mode = modeFrom(userSettings);
    instances.push({
      id,
      platform: "codex-cli",
      version: null,
      scope: "user",
      projectPath: null,
      configFiles: [userFile],
      defaultMode: mode.value,
      defaultModeSourceFile: mode.sourceFile,
      permissionRules: [],
      sandbox: sandboxFrom(userSettings),
      hooks: [],
      additionalDirectories: [],
      controls: [],
      notes: notesFrom(userSettings, "user", { level: null, file: null, projectFile: null }, profiles),
    });
    mcpServers.push(...mcpServersFrom(userData, userFile, id));
  }

  const projectsTable = table(userData?.projects) ?? {};
  const trustFor = (abs: string): string | null => {
    for (const [key, v] of Object.entries(projectsTable)) {
      if (path.resolve(key) === abs) return str(table(v)?.trust_level);
    }
    return null;
  };

  const seen = new Set<string>();
  for (const root of projectRoots) {
    const abs = path.resolve(root);
    if (seen.has(abs)) continue;
    seen.add(abs);
    const projectFile = path.join(abs, ".codex", "config.toml");
    const projectData = await readTomlConfig(projectFile, issues);
    if (!projectData) continue;

    const level = trustFor(abs);
    const projectSf: SettingsFile = { file: projectFile, level: "project", data: projectData };
    // Only a trusted project's config participates in the merge (vendor gating);
    // otherwise its values are shown as declared-but-inactive via the notes.
    const effective = (level === "trusted" ? [projectSf, ...userSettings] : [...userSettings]).sort(
      (a, b) => LEVEL_RANK[a.level] - LEVEL_RANK[b.level],
    );
    const id = `codex-cli:project:${hash8(abs)}`;
    const mode = modeFrom(effective);
    instances.push({
      id,
      platform: "codex-cli",
      version: null,
      scope: "project",
      projectPath: abs,
      configFiles: [...userSettings.map((s) => s.file), projectFile],
      defaultMode: mode.value,
      defaultModeSourceFile: mode.sourceFile,
      permissionRules: [],
      sandbox: sandboxFrom(effective),
      hooks: [],
      additionalDirectories: [],
      controls: [],
      notes: notesFrom(
        level === "trusted" ? effective : [...effective, projectSf],
        "project",
        { level, file: userFile, projectFile },
        0,
      ),
    });
    mcpServers.push(...mcpServersFrom(projectData, projectFile, id));
  }

  return { instances, mcpServers, issues };
}
