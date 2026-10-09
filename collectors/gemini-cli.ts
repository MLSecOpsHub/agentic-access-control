import { promises as fs } from "fs";
import os from "os";
import path from "path";
import type {
  AgentInstance,
  Effect,
  McpServer,
  PermissionRule,
  SandboxConfig,
  SourceLevel,
} from "../lib/schema";
import { redact } from "../lib/redact";
import { asStringArray, hash8, readJsonConfig, type ParseIssue } from "./util";
import { mcpServersFrom, parseHooksBlock, parseTool, type CollectorResult } from "./claude-code";

// Gemini CLI collector — spec: docs/collectors.md §4. Vendor docs verified
// 2026-10-09 (docs/reference/configuration.md, docs/cli/settings.md,
// docs/cli/trusted-folders.md, docs/cli/sandbox.md, docs/reference/policy-engine.md):
//   - Settings tiers, highest precedence first: system settings
//     (/etc/gemini-cli/settings.json; macOS /Library/Application Support/GeminiCli/
//     settings.json) > project <dir>/.gemini/settings.json > user ~/.gemini/settings.json
//     > system-defaults file (lowest; not collected — rare, admin-provided).
//   - `tools.allowed`: tool names that bypass the confirmation dialog → allow.
//     `tools.exclude`: tools removed from discovery → deny. `tools.core` is an
//     availability allowlist, not an approval grant → recorded as a note only.
//   - `general.defaultApprovalMode`: default | auto_edit | plan. YOLO exists only
//     as a CLI flag / env, i.e. the `flag` tier a filesystem collector cannot see.
//   - `tools.sandbox` (bool | profile string | command) and `tools.sandboxNetworkAccess`.
//   - `mcpServers` (top level, `url` = SSE, `httpUrl` = streamable HTTP, per-server
//     `trust: true` bypasses confirmation); `mcp.allowed` / `mcp.excluded` lists.
//   - `hooks` block shares Claude Code's shape; `security.folderTrust.enabled`
//     (default true) gates whether project settings and MCP servers load at all.
//   - NOT collected: TOML policy files (~/.gemini/policies, /etc/gemini-cli/policies
//     — needs a TOML dependency, T10) and ~/.gemini/trustedFolders.json. Both are
//     declared on the instance as notes (SR4) instead of silently missing.
//   Legacy flat keys (coreTools, excludeTools, allowedTools, sandbox,
//   allowMCPServers, excludeMCPServers, autoAccept) are read when the nested key
//   is absent, since older installs may not have been migrated.

const LEVEL_RANK: Record<string, number> = { managed: 0, project: 1, user: 2 };
const LEVEL_COUNT = 3;
const EFFECT_RANK: Record<Effect, number> = { deny: 0, ask: 1, allow: 2 };

const SYSTEM_SETTINGS = [
  "/etc/gemini-cli/settings.json",
  "/Library/Application Support/GeminiCli/settings.json",
];

interface SettingsFile {
  file: string;
  level: SourceLevel;
  data: Record<string, unknown>;
}

function get(data: Record<string, unknown>, dotted: string): unknown {
  let cur: unknown = data;
  for (const part of dotted.split(".")) {
    if (typeof cur !== "object" || cur === null) return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

function list(data: Record<string, unknown>, nested: string, legacy: string): string[] | null {
  const v = get(data, nested) ?? data[legacy];
  return Array.isArray(v) ? asStringArray(v) : null;
}

function rulesFrom(sf: SettingsFile): PermissionRule[] {
  const rules: PermissionRule[] = [];
  const push = (effect: Effect, raw: string) => {
    const matcher = redact(raw);
    rules.push({
      effect,
      matcher,
      tool: parseTool(matcher),
      sourceFile: sf.file,
      sourceLevel: sf.level,
      precedenceRank: EFFECT_RANK[effect] * LEVEL_COUNT + LEVEL_RANK[sf.level],
    });
  };
  for (const t of list(sf.data, "tools.exclude", "excludeTools") ?? []) push("deny", t);
  for (const t of list(sf.data, "tools.allowed", "allowedTools") ?? []) push("allow", t);
  return rules;
}

function defaultModeFrom(files: SettingsFile[]): { value: string | null; sourceFile: string | null } {
  for (const sf of files) {
    const v = get(sf.data, "general.defaultApprovalMode");
    if (typeof v === "string") return { value: redact(v), sourceFile: sf.file };
  }
  return { value: null, sourceFile: null };
}

function sandboxFrom(files: SettingsFile[]): SandboxConfig | null {
  let enabled: boolean | null = null;
  let method: string | null = null;
  let network: boolean | null = null;
  const fieldSources: Record<string, string> = {};
  for (const sf of files) {
    const sb = get(sf.data, "tools.sandbox") ?? sf.data.sandbox;
    if (enabled === null && (typeof sb === "boolean" || typeof sb === "string")) {
      enabled = typeof sb === "boolean" ? sb : sb.length > 0;
      method = typeof sb === "string" ? redact(sb) : null;
      fieldSources.enabled = sf.file;
    }
    const net = get(sf.data, "tools.sandboxNetworkAccess");
    if (network === null && typeof net === "boolean") {
      network = net;
      fieldSources.sandboxNetworkAccess = sf.file;
    }
  }
  if (enabled === null && network === null) return null;
  const parts = [
    `Gemini CLI legacy full-process sandbox (tools.sandbox${method ? `: "${method}"` : ""})`,
    network === null ? "network access: unset" : `network access: ${network}`,
    "approval-mode gating is separate from sandboxing",
  ];
  return {
    enabled,
    allowUnsandboxedCommands: null,
    networkAllowlist: [],
    notes: parts.join("; "),
    fieldSources,
  };
}

function enablementFor(files: SettingsFile[]): (name: string) => McpServer["enablement"] {
  let allowed: string[] | null = null;
  let excluded: string[] | null = null;
  for (const sf of files) {
    if (allowed === null) allowed = list(sf.data, "mcp.allowed", "allowMCPServers");
    if (excluded === null) excluded = list(sf.data, "mcp.excluded", "excludeMCPServers");
  }
  const allowedSet = allowed && allowed.length > 0 ? new Set(allowed.map(redact)) : null;
  const excludedSet = new Set((excluded ?? []).map(redact));
  return (name) => {
    if (excludedSet.has(name)) return "disabled";
    if (allowedSet) return allowedSet.has(name) ? "enabled" : "disabled";
    return null;
  };
}

function trustedServerNames(data: Record<string, unknown>): string[] {
  const block = data.mcpServers;
  if (typeof block !== "object" || block === null) return [];
  return Object.entries(block as Record<string, unknown>)
    .filter(([, cfg]) => typeof cfg === "object" && cfg !== null && (cfg as Record<string, unknown>).trust === true)
    .map(([name]) => redact(name));
}

function notesFrom(files: SettingsFile[], scope: "user" | "project"): string[] {
  const notes: string[] = [];
  for (const sf of files) {
    const core = list(sf.data, "tools.core", "coreTools");
    if (core && core.length > 0) {
      notes.push(
        `tools.core in ${sf.file} restricts the built-in tool set to: ${core.map(redact).join(", ")} — an availability allowlist, not an approval grant (listed tools still prompt unless also in tools.allowed).`,
      );
    }
    if (sf.data.autoAccept === true) {
      notes.push(`autoAccept: true in ${sf.file} (legacy key) — read-only tool calls auto-approved per vendor docs.`);
    }
    if (get(sf.data, "hooksConfig.enabled") === false) {
      notes.push(`hooksConfig.enabled: false in ${sf.file} — hooks listed from this tier are declared but disabled.`);
    }
    for (const name of trustedServerNames(sf.data)) {
      notes.push(`MCP server "${name}" in ${sf.file} declares trust: true — vendor docs: tool-call confirmations are bypassed for this server.`);
    }
  }
  const trustSetting = files.map((sf) => get(sf.data, "security.folderTrust.enabled")).find((v) => typeof v === "boolean");
  if (scope === "project") {
    notes.push(
      trustSetting === false
        ? "Folder trust is disabled (security.folderTrust.enabled: false): project-tier settings and MCP servers load unconditionally."
        : "Folder trust is enabled (vendor default): project-tier settings and MCP servers load only if this folder is trusted. Trust state (~/.gemini/trustedFolders.json) is not collected — read project-tier rows as conditional.",
    );
  }
  notes.push(
    "Gemini CLI has no documented allow/ask/deny evaluation order over these lists; rows are grouped by effect for display (deny = tools.exclude, allow = tools.allowed). TOML policy files (~/.gemini/policies, /etc/gemini-cli/policies) and the YOLO CLI flag are not collected.",
  );
  return notes;
}

async function loadSettings(
  candidates: Array<{ file: string; level: SourceLevel }>,
  issues: ParseIssue[],
): Promise<SettingsFile[]> {
  const out: SettingsFile[] = [];
  for (const c of candidates) {
    const data = await readJsonConfig(c.file, issues);
    if (data) out.push({ ...c, data });
  }
  return out.sort((a, b) => LEVEL_RANK[a.level] - LEVEL_RANK[b.level]);
}

async function isDir(p: string): Promise<boolean> {
  try {
    return (await fs.lstat(p)).isDirectory();
  } catch {
    return false;
  }
}

export async function collectGeminiCli(projectRoots: string[]): Promise<CollectorResult> {
  const issues: ParseIssue[] = [];
  const home = os.homedir();
  const instances: AgentInstance[] = [];
  const mcpServers: McpServer[] = [];

  const userCandidates = [
    ...SYSTEM_SETTINGS.map((file) => ({ file, level: "managed" as const })),
    { file: path.join(home, ".gemini", "settings.json"), level: "user" as const },
  ];
  const userSettings = await loadSettings(userCandidates, issues);

  if (userSettings.length > 0) {
    const id = "gemini-cli:user";
    const mode = defaultModeFrom(userSettings);
    instances.push({
      id,
      platform: "gemini-cli",
      version: null,
      scope: "user",
      projectPath: null,
      configFiles: userSettings.map((s) => s.file),
      defaultMode: mode.value,
      defaultModeSourceFile: mode.sourceFile,
      permissionRules: userSettings.flatMap(rulesFrom),
      sandbox: sandboxFrom(userSettings),
      hooks: userSettings.flatMap((sf) => parseHooksBlock(sf.data.hooks, sf.file)),
      notes: notesFrom(userSettings, "user"),
    });
    const enablement = enablementFor(userSettings);
    for (const sf of userSettings) {
      for (const srv of mcpServersFrom(sf.data, sf.file, id, "sse")) {
        mcpServers.push({ ...srv, enablement: enablement(srv.name) });
      }
    }
  }

  const seen = new Set<string>();
  for (const root of projectRoots) {
    const abs = path.resolve(root);
    if (seen.has(abs)) continue;
    seen.add(abs);
    // Gemini's workspace is the launch directory itself (no git-root walk-up documented).
    const projectFile = path.join(abs, ".gemini", "settings.json");
    if (!(await isDir(path.join(abs, ".gemini")))) continue;
    const settings = await loadSettings(
      [...userCandidates, { file: projectFile, level: "project" as const }],
      issues,
    );
    const projectSettings = settings.filter((s) => s.level === "project");
    if (projectSettings.length === 0) continue;

    const id = `gemini-cli:project:${hash8(abs)}`;
    const mode = defaultModeFrom(settings);
    instances.push({
      id,
      platform: "gemini-cli",
      version: null,
      scope: "project",
      projectPath: abs,
      configFiles: settings.map((s) => s.file),
      defaultMode: mode.value,
      defaultModeSourceFile: mode.sourceFile,
      // Full effective set (system+user+project), matching the Claude Code collector.
      permissionRules: settings.flatMap(rulesFrom),
      sandbox: sandboxFrom(settings),
      hooks: settings.flatMap((sf) => parseHooksBlock(sf.data.hooks, sf.file)),
      notes: notesFrom(settings, "project"),
    });
    const enablement = enablementFor(settings);
    for (const sf of projectSettings) {
      for (const srv of mcpServersFrom(sf.data, sf.file, id, "sse")) {
        mcpServers.push({ ...srv, enablement: enablement(srv.name) });
      }
    }
  }

  return { instances, mcpServers, issues };
}
