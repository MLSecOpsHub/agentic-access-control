import { promises as fs } from "fs";
import os from "os";
import path from "path";
import type {
  AdditionalDirectory,
  AgentInstance,
  Control,
  Effect,
  Hook,
  McpServer,
  PermissionRule,
  SandboxConfig,
  SourceLevel,
} from "../lib/schema";
import { redact, truncate } from "../lib/redact";
import { asStringArray, hash8, readJsonConfig, type ParseIssue } from "./util";

// Claude Code collector — spec: docs/collectors.md §2.
// Precedence engine (hardening Step 5) per first-party docs, verified 2026-08-13:
//   - Permission RULES merge across all settings files and evaluate globally
//     as deny → ask → allow; tier never overrides effect. A deny in any tier
//     outranks an allow in any other tier.
//   - Tier precedence applies to SINGLE-VALUE settings (defaultMode, sandbox
//     fields): managed > command line > local project > shared project > user.

const LEVEL_RANK: Record<SourceLevel, number> = { managed: 0, flag: 1, local: 2, project: 3, user: 4 };
const LEVEL_COUNT = 5;
const EFFECT_RANK: Record<Effect, number> = { deny: 0, ask: 1, allow: 2 };

export interface CollectorResult {
  instances: AgentInstance[];
  mcpServers: McpServer[];
  issues: ParseIssue[];
}

interface SettingsFile {
  file: string;
  level: SourceLevel;
  data: Record<string, unknown>;
}

export function parseTool(matcher: string): string | null {
  const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|$)/.exec(matcher);
  return m ? m[1] : null;
}

function rulesFrom(sf: SettingsFile): PermissionRule[] {
  const perms = (sf.data.permissions ?? {}) as Record<string, unknown>;
  const rules: PermissionRule[] = [];
  for (const effect of ["deny", "ask", "allow"] as const) {
    for (const raw of asStringArray(perms[effect])) {
      const matcher = redact(raw);
      rules.push({
        effect,
        matcher,
        tool: parseTool(matcher),
        sourceFile: sf.file,
        sourceLevel: sf.level,
        // Effect-first: any deny ranks ahead of any ask, any ask ahead of any
        // allow, regardless of tier. Tier only breaks ties within an effect.
        precedenceRank: EFFECT_RANK[effect] * LEVEL_COUNT + LEVEL_RANK[sf.level],
      });
    }
  }
  return rules;
}

// `hooks: { <Event>: [ { matcher?, hooks: [ { type, command } ] } ] }` — the
// shape Claude Code and Gemini CLI share.
export function parseHooksBlock(hooks: unknown, sourceFile: string): Hook[] {
  if (typeof hooks !== "object" || hooks === null) return [];
  const out: Hook[] = [];
  for (const [rawEvent, entries] of Object.entries(hooks as Record<string, unknown>)) {
    const event = redact(rawEvent);
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (typeof entry !== "object" || entry === null) continue;
      const e = entry as Record<string, unknown>;
      const matcher = typeof e.matcher === "string" ? redact(e.matcher) : null;
      const inner = Array.isArray(e.hooks) ? e.hooks : [];
      for (const h of inner) {
        if (typeof h !== "object" || h === null) continue;
        const cmd = (h as Record<string, unknown>).command;
        if (typeof cmd === "string") {
          out.push({ event, matcher, commandPreview: truncate(redact(cmd)), sourceFile });
        }
      }
    }
  }
  return out;
}

function hooksFrom(sf: SettingsFile): Hook[] {
  return parseHooksBlock(sf.data.hooks, sf.file);
}

const obj = (v: unknown): Record<string, unknown> | null =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
const perms = (d: Record<string, unknown>) => obj(d.permissions) ?? {};

function sandboxFrom(files: SettingsFile[]): SandboxConfig | null {
  // Per-field tier merge (Step 5): each field is taken independently from the
  // highest-precedence file that defines it — `files` arrives sorted by level
  // rank. Provenance per field lands in fieldSources for H6 attribution.
  // Vendor semantics verified 2026-10-11: the sandbox covers shell commands
  // only (file tools, MCP servers and hooks run outside it); it is off by
  // default; autoAllowBashIfSandboxed defaults to true; excludedCommands run
  // unsandboxed; allowUnsandboxedCommands may be a string or a boolean.
  let found = false;
  let enabled: boolean | null = null;
  let allowUnsandboxedCommands: boolean | null = null;
  let allowUnsandboxedRaw: string | null = null;
  let autoAllowBashIfSandboxed: boolean | null = null;
  let excludedCommands: string[] = [];
  let networkAllowlist: string[] = [];
  const fsRules: string[] = [];
  const fieldSources: Record<string, string> = {};

  for (const sf of files) {
    const s = obj(sf.data.sandbox);
    if (!s) continue;
    found = true;
    if (enabled === null && typeof s.enabled === "boolean") {
      enabled = s.enabled;
      fieldSources.enabled = sf.file;
    }
    if (allowUnsandboxedCommands === null && allowUnsandboxedRaw === null) {
      if (typeof s.allowUnsandboxedCommands === "boolean") {
        allowUnsandboxedCommands = s.allowUnsandboxedCommands;
        fieldSources.allowUnsandboxedCommands = sf.file;
      } else if (typeof s.allowUnsandboxedCommands === "string") {
        allowUnsandboxedRaw = redact(s.allowUnsandboxedCommands);
        fieldSources.allowUnsandboxedCommands = sf.file;
      }
    }
    if (autoAllowBashIfSandboxed === null && typeof s.autoAllowBashIfSandboxed === "boolean") {
      autoAllowBashIfSandboxed = s.autoAllowBashIfSandboxed;
      fieldSources.autoAllowBashIfSandboxed = sf.file;
    }
    const excluded = asStringArray(s.excludedCommands).map(redact);
    if (!("excludedCommands" in fieldSources) && excluded.length > 0) {
      excludedCommands = excluded;
      fieldSources.excludedCommands = sf.file;
    }
    const network = obj(s.network) ?? {};
    const allowlist = [
      ...asStringArray(network.allowedDomains),
      ...asStringArray(network.allowedHosts),
      ...asStringArray(s.allowedDomains),
    ].map(redact);
    if (!("networkAllowlist" in fieldSources) && allowlist.length > 0) {
      networkAllowlist = allowlist;
      fieldSources.networkAllowlist = sf.file;
    }
    const fsBlock = obj(s.filesystem) ?? {};
    for (const key of ["denyRead", "allowRead", "allowWrite", "denyWrite"]) {
      const n = asStringArray(fsBlock[key]).length;
      if (n > 0) fsRules.push(`${key} ${n}`);
    }
    for (const key of ["allowUnixSockets", "allowLocalBinding", "enableWeakerNestedSandbox", "failIfUnavailable"]) {
      const v = key in network ? network[key] : s[key];
      if (typeof v === "boolean" || Array.isArray(v)) fsRules.push(`${key}: ${Array.isArray(v) ? `${v.length} entries` : v}`);
    }
  }

  if (!found) return null;
  const parts = [
    "Covers shell commands only (vendor): file tools, MCP servers and hooks run outside the sandbox",
    `autoAllowBashIfSandboxed: ${autoAllowBashIfSandboxed ?? "unset → vendor default true (sandboxed commands run without prompts)"}`,
    allowUnsandboxedRaw !== null ? `allowUnsandboxedCommands: "${allowUnsandboxedRaw}"` : null,
    fsRules.length > 0 ? `filesystem/network rules: ${fsRules.join(", ")}` : null,
    "Egress filtering is hostname-only per vendor docs (TLS-blind; see landscape §1)",
  ].filter((p): p is string => p !== null);
  return {
    enabled,
    allowUnsandboxedCommands,
    networkAllowlist,
    autoAllowBashIfSandboxed,
    excludedCommands,
    notes: parts.join("; "),
    fieldSources,
  };
}

// Permission-relevant single-value settings beyond rules/mode/sandbox, from
// the highest-precedence file that defines each (vendor settings reference,
// verified 2026-10-11). Shown as a table on the instance page; H9 reads it.
const CONTROL_KEYS: Array<{ key: string; pick: (d: Record<string, unknown>) => unknown }> = [
  { key: "skipDangerousModePermissionPrompt", pick: (d) => d.skipDangerousModePermissionPrompt },
  { key: "permissions.disableBypassPermissionsMode", pick: (d) => perms(d).disableBypassPermissionsMode },
  { key: "permissions.disableAutoMode", pick: (d) => perms(d).disableAutoMode ?? d.disableAutoMode },
  { key: "permissions.blockReadsOutsideWorkingDirectories", pick: (d) => perms(d).blockReadsOutsideWorkingDirectories },
  { key: "enableAllProjectMcpServers", pick: (d) => d.enableAllProjectMcpServers },
  { key: "disableAllHooks", pick: (d) => d.disableAllHooks },
  { key: "allowManagedPermissionRulesOnly", pick: (d) => d.allowManagedPermissionRulesOnly },
  { key: "allowManagedHooksOnly", pick: (d) => d.allowManagedHooksOnly },
  { key: "useAutoModeDuringPlan", pick: (d) => d.useAutoModeDuringPlan },
  { key: "skipAutoPermissionPrompt", pick: (d) => d.skipAutoPermissionPrompt },
  { key: "autoMode.classifyAllShell", pick: (d) => obj(d.autoMode)?.classifyAllShell },
  { key: "sandbox.failIfUnavailable", pick: (d) => obj(d.sandbox)?.failIfUnavailable },
];

function controlsFrom(files: SettingsFile[]): Control[] {
  const out: Control[] = [];
  const seen = new Set<string>();
  for (const sf of files) {
    for (const c of CONTROL_KEYS) {
      if (seen.has(c.key)) continue;
      const v = c.pick(sf.data);
      if (typeof v === "boolean" || typeof v === "string") {
        seen.add(c.key);
        out.push({ key: c.key, value: redact(String(v)), sourceFile: sf.file });
      }
    }
  }
  return out;
}

function additionalDirectoriesFrom(files: SettingsFile[]): AdditionalDirectory[] {
  return files.flatMap((sf) =>
    asStringArray(perms(sf.data).additionalDirectories).map((p) => ({ path: redact(p), sourceFile: sf.file })),
  );
}

// Vendor wording for each permission mode (permission-modes reference,
// verified 2026-10-11) so the instance page says what a mode means.
const MODE_TEXT: Record<string, string> = {
  default: "default (Manual): reads run without asking; edits, shell commands and network requests prompt.",
  acceptEdits: "acceptEdits: file edits and common filesystem commands in the working directories run without prompts.",
  plan: "plan: reads only, plus classifier-approved commands when auto mode is available.",
  auto: "auto: everything runs, with a background classifier reviewing actions instead of you — the vendor's built-in starting mode for interactive sessions since Claude Code v2.1.283.",
  dontAsk: "dontAsk: anything that would prompt is denied; pre-approved tools and reads in the working directories still run.",
  bypassPermissions: "bypassPermissions: skips permission prompts — vendor: isolated containers and VMs only.",
};

function settingsNotesFrom(
  files: SettingsFile[],
  mode: { value: string | null; sourceFile: string | null },
  projectPath: string | null,
  sandbox: SandboxConfig | null,
  additionalDirectories: AdditionalDirectory[],
): string[] {
  const notes: string[] = [];
  if (mode.value && MODE_TEXT[mode.value]) {
    notes.push(`Mode semantics (vendor docs): ${MODE_TEXT[mode.value]} Source: ${mode.sourceFile}.`);
  } else if (mode.value) {
    notes.push(`Mode "${mode.value}" is not in the vendor's documented mode list (2026-10-11) — shown as declared.`);
  }
  if (mode.value === "auto" && projectPath && mode.sourceFile?.startsWith(projectPath + path.sep)) {
    notes.push(
      `Vendor caveat: "auto" set in .claude/settings.json or .claude/settings.local.json does not take effect — sessions use the built-in default instead of this declaration (${mode.sourceFile}).`,
    );
  }
  const first = <T,>(pick: (d: Record<string, unknown>) => T | null) => {
    for (const sf of files) {
      const v = pick(sf.data);
      if (v !== null) return { value: v, file: sf.file };
    }
    return null;
  };
  const autoMode = first((d) => obj(d.autoMode));
  if (autoMode) {
    notes.push(
      `autoMode configured in ${autoMode.file} (keys: ${Object.keys(autoMode.value).map(redact).join(", ") || "none"}) — custom classifier allow/deny rules and trusted infrastructure; contents are not collected.`,
    );
  }
  const env = first((d) => obj(d.env));
  if (env && Object.keys(env.value).length > 0) {
    const names = Object.keys(env.value).map(redact);
    notes.push(
      `env sets ${names.length} environment variable(s) for every session in ${env.file} (names only: ${names.slice(0, 8).join(", ")}${names.length > 8 ? ", …" : ""}).`,
    );
  }
  for (const key of ["deniedMcpServers", "allowedMcpServers"] as const) {
    const list = first((d) => (Array.isArray(d[key]) ? d[key] : null));
    if (list) {
      notes.push(
        key === "deniedMcpServers"
          ? `deniedMcpServers (${list.value.length}) in ${list.file} block servers by name, URL or command; exact name/URL/command matches are reflected as enablement = disabled.`
          : `allowedMcpServers (${list.value.length}) in ${list.file} restrict which servers can be added; not applied to enablement (SR4).`,
      );
    }
  }
  const noHooks = first((d) => (d.disableAllHooks === true ? true : null));
  if (noHooks) notes.push(`disableAllHooks: true in ${noHooks.file} — hooks listed for this instance are declared but turned off.`);
  const disableBypass = first((d) => (perms(d).disableBypassPermissionsMode !== undefined ? String(perms(d).disableBypassPermissionsMode) : null));
  if (disableBypass && mode.value === "bypassPermissions") {
    notes.push(`permissions.disableBypassPermissionsMode is set in ${disableBypass.file} — vendor: prevents entering bypassPermissions mode, so the configured bypass default above is inert while that control holds.`);
  }
  if (additionalDirectories.length > 0) {
    notes.push(
      `permissions.additionalDirectories grants file access outside the project without prompts: ${additionalDirectories.map((d) => d.path).join(", ")} — applies after the folder is trusted (vendor).`,
    );
  }
  if (sandbox && sandbox.enabled !== false && sandbox.excludedCommands.length > 0) {
    notes.push(`sandbox.excludedCommands lists ${sandbox.excludedCommands.length} pattern(s) that run outside the sandbox (no filesystem limits, no network proxy).`);
  }
  return notes;
}

// Approval sources for project .mcp.json servers (vendor MCP + settings
// references, verified 2026-10-11): the prompt choice recorded in ~/.claude.json,
// plus enabledMcpjsonServers / disabledMcpjsonServers / enableAllProjectMcpServers
// in any settings file — except that approvals committed to the project's own
// settings are ignored until the folder is trusted. Rejections always count
// (conservative). deniedMcpServers blocks by name, URL or command.
interface McpApprovals {
  enabled: Set<string>;
  disabled: Set<string>;
  enableAll: boolean;
  denied: Array<Record<string, unknown>>;
  notes: string[];
}

function mcpApprovalsFrom(files: SettingsFile[], trusted: boolean): McpApprovals {
  const out: McpApprovals = { enabled: new Set(), disabled: new Set(), enableAll: false, denied: [], notes: [] };
  let enableAllSeen = false;
  for (const sf of files) {
    const approvalsCount = sf.level !== "project" || trusted;
    for (const n of asStringArray(sf.data.disabledMcpjsonServers)) out.disabled.add(redact(n));
    const enabled = asStringArray(sf.data.enabledMcpjsonServers);
    if (enabled.length > 0) {
      if (approvalsCount) for (const n of enabled) out.enabled.add(redact(n));
      else out.notes.push(`enabledMcpjsonServers in ${sf.file} is ignored by the vendor until this folder is trusted — not counted as approval.`);
    }
    if (!enableAllSeen && typeof sf.data.enableAllProjectMcpServers === "boolean") {
      if (approvalsCount) {
        enableAllSeen = true;
        out.enableAll = sf.data.enableAllProjectMcpServers;
      } else {
        out.notes.push(`enableAllProjectMcpServers in ${sf.file} is ignored by the vendor until this folder is trusted — not counted as approval.`);
      }
    }
    if (Array.isArray(sf.data.deniedMcpServers)) {
      for (const d of sf.data.deniedMcpServers) {
        const o = obj(d);
        if (o) out.denied.push(o);
      }
    }
  }
  return out;
}

function deniedByPolicy(denied: Array<Record<string, unknown>>, srv: McpServer): boolean {
  return denied.some(
    (d) =>
      (typeof d.serverName === "string" && redact(d.serverName) === srv.name) ||
      (typeof d.serverUrl === "string" && redact(d.serverUrl) === srv.commandOrUrl) ||
      (typeof d.serverCommand === "string" && redact(d.serverCommand) === srv.commandOrUrl),
  );
}

function defaultModeFrom(files: SettingsFile[]): { value: string | null; sourceFile: string | null } {
  // First hit in precedence order wins — `files` arrives sorted by level rank.
  for (const sf of files) {
    const perms = (sf.data.permissions ?? {}) as Record<string, unknown>;
    if (typeof perms.defaultMode === "string") {
      return { value: redact(perms.defaultMode), sourceFile: sf.file };
    }
  }
  return { value: null, sourceFile: null };
}

// Shared `mcpServers` block parser. `bareUrlTransport` is what a `url` field
// means when no `type` is declared: Claude Code documents `url` as HTTP (SSE
// only with `type: "sse"`); Gemini CLI documents `url` as SSE and `httpUrl`
// as streamable HTTP.
export function mcpServersFrom(
  data: Record<string, unknown>,
  sourceFile: string,
  instanceId: string,
  bareUrlTransport: "http" | "sse" = "http",
): McpServer[] {
  const block = data.mcpServers;
  if (typeof block !== "object" || block === null) return [];
  const out: McpServer[] = [];
  for (const [name, cfgRaw] of Object.entries(block as Record<string, unknown>)) {
    if (typeof cfgRaw !== "object" || cfgRaw === null) continue;
    const cfg = cfgRaw as Record<string, unknown>;
    const httpUrl = typeof cfg.httpUrl === "string" ? cfg.httpUrl : null;
    const url = typeof cfg.url === "string" ? cfg.url : null;
    const command = typeof cfg.command === "string" ? cfg.command : null;
    const declaredType = typeof cfg.type === "string" ? cfg.type : null;
    const transport: McpServer["transport"] =
      declaredType === "sse"
        ? "sse"
        : httpUrl
          ? "http"
          : url
            ? bareUrlTransport
            : command
              ? "stdio"
              : "unknown";
    out.push({
      name: redact(name),
      transport,
      commandOrUrl: redact(httpUrl ?? url ?? command ?? ""),
      args: asStringArray(cfg.args).map(redact),
      // SR2: env VALUES are dropped unconditionally — key names only.
      envKeys: typeof cfg.env === "object" && cfg.env !== null ? Object.keys(cfg.env) : [],
      declaredTools: null, // never obtained by executing the server (SR1)
      enablement: null,
      sourceFile,
      instanceId,
    });
  }
  return out;
}

const MANAGED_PATHS = [
  "/etc/claude-code/managed-settings.json",
  "/Library/Application Support/ClaudeCode/managed-settings.json",
];

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

// Vendor semantics: project settings live at the GIT ROOT — scanning a nested
// package directory still applies <gitRoot>/.claude/settings[.local].json.
// Walk up looking for a .git entry (directory, or file for worktrees) using
// read-only existence checks (SR1). A symlinked .git is not treated as a
// repository root (T4). No .git anywhere up the chain → the scanned directory
// itself is the project root.
async function resolveProjectRoot(scanned: string): Promise<string> {
  let dir = scanned;
  for (;;) {
    try {
      const st = await fs.lstat(path.join(dir, ".git"));
      if (st.isDirectory() || st.isFile()) return dir;
    } catch {
      // no .git at this level
    }
    const parent = path.dirname(dir);
    if (parent === dir) return scanned;
    dir = parent;
  }
}

// ~/.claude.json entries under `projects` are keyed by the directory Claude
// was launched from; entries for the git root or the scanned directory both
// belong to this project instance.
function projectEntriesFor(
  claudeJson: Record<string, unknown> | undefined,
  targets: Set<string>,
): Array<Record<string, unknown>> {
  const projects = claudeJson?.projects;
  if (typeof projects !== "object" || projects === null) return [];
  return Object.entries(projects as Record<string, unknown>)
    .filter(([key, v]) => targets.has(path.resolve(key)) && typeof v === "object" && v !== null)
    .map(([, v]) => v as Record<string, unknown>);
}

// Default project roots when the CLI is given none: the keys of the `projects`
// map in ~/.claude.json — every directory Claude Code has been launched from.
// Read-only existence checks only (SR1); symlinked entries are not followed
// (T4); $HOME and the filesystem root are excluded because treating them as a
// project would misfile user-tier settings as project-tier declarations.
export async function discoverProjectRoots(): Promise<string[]> {
  const home = os.homedir();
  const claudeJson = await readJsonConfig(path.join(home, ".claude.json"), []);
  const projects = claudeJson?.projects;
  if (typeof projects !== "object" || projects === null) return [];
  const out = new Set<string>();
  for (const key of Object.keys(projects as Record<string, unknown>)) {
    if (!path.isAbsolute(key)) continue;
    const abs = path.resolve(key);
    if (abs === path.resolve(home) || abs === path.parse(abs).root) continue;
    try {
      const st = await fs.lstat(abs);
      if (!st.isDirectory()) continue;
    } catch {
      continue;
    }
    out.add(abs);
  }
  return [...out].sort();
}

// ~/.claude.json project entries also record the folder-trust dialog outcome
// and, on older installs, a per-project `allowedTools` list. Both become
// instance notes: trust gates project-sourced configuration in the vendor's
// own flow, and legacy grants must not be merged into declarations that
// current versions ignore (SR4). Never read the entries' usage/cost telemetry.
function trustNotesFrom(entries: Array<Record<string, unknown>>, file: string): string[] {
  const notes: string[] = [];
  const accepted = entries.map((e) => e.hasTrustDialogAccepted).find((v) => typeof v === "boolean");
  if (accepted === true) {
    notes.push(`Folder trust: accepted for this project (hasTrustDialogAccepted: true in ${file}).`);
  } else if (accepted === false) {
    notes.push(
      `Folder trust: not accepted for this project (hasTrustDialogAccepted: false in ${file}) — Claude Code gates project-sourced configuration behind its trust dialog; read project-tier rows as conditional.`,
    );
  } else {
    notes.push(`Folder trust: no recorded decision for this project in ${file} — read project-tier rows as conditional.`);
  }
  const legacy = entries.flatMap((e) => asStringArray(e.allowedTools));
  if (legacy.length > 0) {
    const preview = legacy.slice(0, 5).map(redact).join(", ") + (legacy.length > 5 ? ", …" : "");
    notes.push(
      `Legacy per-project allowedTools list in ${file} (${legacy.length}): ${preview} — honoured by older Claude Code versions only; not merged into the declarations above (SR4). Review and remove if stale.`,
    );
  }
  return notes;
}

export async function collectClaudeCode(projectRoots: string[]): Promise<CollectorResult> {
  const issues: ParseIssue[] = [];
  const home = os.homedir();
  const instances: AgentInstance[] = [];
  const mcpServers: McpServer[] = [];

  const userCandidates = [
    ...MANAGED_PATHS.map((file) => ({ file, level: "managed" as const })),
    { file: path.join(home, ".claude", "settings.json"), level: "user" as const },
  ];
  const userSettings = await loadSettings(userCandidates, issues);

  // ~/.claude.json carries user-level MCP server registrations plus
  // per-project entries (MCP servers and .mcp.json enable/disable choices).
  const claudeJsonPath = path.join(home, ".claude.json");
  const claudeJson = await readJsonConfig(claudeJsonPath, issues);

  const userMode = defaultModeFrom(userSettings);
  const userSandbox = sandboxFrom(userSettings);
  const userDirs = additionalDirectoriesFrom(userSettings);
  const userApprovals = mcpApprovalsFrom(userSettings, true);
  const userInstance: AgentInstance = {
    id: "claude-code:user",
    platform: "claude-code",
    version: null, // best-effort field; no subprocess in v1 keeps SR1 trivially auditable
    scope: "user",
    projectPath: null,
    configFiles: [
      ...userSettings.map((s) => s.file),
      ...(claudeJson ? [claudeJsonPath] : []),
    ],
    defaultMode: userMode.value,
    defaultModeSourceFile: userMode.sourceFile,
    permissionRules: userSettings.flatMap(rulesFrom),
    sandbox: userSandbox,
    hooks: userSettings.flatMap(hooksFrom),
    notes: [...settingsNotesFrom(userSettings, userMode, null, userSandbox, userDirs), ...userApprovals.notes],
    additionalDirectories: userDirs,
    controls: controlsFrom(userSettings),
  };
  if (userInstance.configFiles.length > 0) {
    instances.push(userInstance);
    if (claudeJson) {
      for (const srv of mcpServersFrom(claudeJson, claudeJsonPath, userInstance.id)) {
        mcpServers.push(deniedByPolicy(userApprovals.denied, srv) ? { ...srv, enablement: "disabled" } : srv);
      }
    }
  }

  const seenRoots = new Set<string>();
  for (const root of projectRoots) {
    const scanned = path.resolve(root);
    const abs = await resolveProjectRoot(scanned);
    if (seenRoots.has(abs)) continue;
    seenRoots.add(abs);

    const projCandidates = [
      ...userCandidates,
      { file: path.join(abs, ".claude", "settings.local.json"), level: "local" as const },
      { file: path.join(abs, ".claude", "settings.json"), level: "project" as const },
    ];
    const settings = await loadSettings(projCandidates, issues);
    const mcpJsonPath = path.join(abs, ".mcp.json");
    const mcpJson = await readJsonConfig(mcpJsonPath, issues);
    const entries = projectEntriesFor(claudeJson, new Set([abs, scanned]));

    // A bare ~/.claude.json project entry (Claude was merely launched here)
    // does not make a project instance — only permission-relevant content
    // does. Otherwise discovered roots would each render as an instance that
    // just repeats the user tier.
    const entriesWithContent = entries.filter(
      (e) =>
        (typeof e.mcpServers === "object" && e.mcpServers !== null && Object.keys(e.mcpServers).length > 0) ||
        asStringArray(e.enabledMcpjsonServers).length > 0 ||
        asStringArray(e.disabledMcpjsonServers).length > 0,
    );
    const hasProjectConfig =
      settings.some((s) => s.level === "project" || s.level === "local") ||
      !!mcpJson ||
      entriesWithContent.length > 0;
    if (!hasProjectConfig) continue;

    const id = `claude-code:project:${hash8(abs)}`;
    const mode = defaultModeFrom(settings);
    const trusted = entries.some((e) => e.hasTrustDialogAccepted === true);
    const sandbox = sandboxFrom(settings);
    const dirs = additionalDirectoriesFrom(settings);
    const approvals = mcpApprovalsFrom(settings, trusted);
    instances.push({
      id,
      platform: "claude-code",
      version: null,
      scope: "project",
      projectPath: abs,
      configFiles: [
        ...settings.map((s) => s.file),
        ...(mcpJson ? [mcpJsonPath] : []),
        ...(entriesWithContent.length > 0 ? [claudeJsonPath] : []),
      ],
      defaultMode: mode.value,
      defaultModeSourceFile: mode.sourceFile,
      // Full effective set (managed+user+local+project), not just project-file rules.
      permissionRules: settings.flatMap(rulesFrom),
      sandbox,
      hooks: settings.flatMap(hooksFrom),
      notes: [
        ...trustNotesFrom(entries, claudeJsonPath),
        ...settingsNotesFrom(settings, mode, abs, sandbox, dirs),
        ...approvals.notes,
      ],
      additionalDirectories: dirs,
      controls: controlsFrom(settings),
    });

    if (mcpJson) {
      // Approval state for .mcp.json-declared servers: the prompt choice in
      // the matching ~/.claude.json project entry, plus settings-file
      // approvals (trust-gated for the project's own files). Disabled wins
      // on conflict. Null = no recorded choice — NOT "active" (SR4).
      for (const e of entries) {
        for (const n of asStringArray(e.enabledMcpjsonServers)) approvals.enabled.add(redact(n));
        for (const n of asStringArray(e.disabledMcpjsonServers)) approvals.disabled.add(redact(n));
      }
      for (const srv of mcpServersFrom(mcpJson, mcpJsonPath, id)) {
        const enablement =
          approvals.disabled.has(srv.name) || deniedByPolicy(approvals.denied, srv)
            ? "disabled"
            : approvals.enabled.has(srv.name) || approvals.enableAll
              ? "enabled"
              : null;
        mcpServers.push({ ...srv, enablement });
      }
    }
    // Project-scoped MCP servers registered directly in ~/.claude.json.
    for (const entry of entries) {
      for (const srv of mcpServersFrom(entry, claudeJsonPath, id)) {
        mcpServers.push(deniedByPolicy(approvals.denied, srv) ? { ...srv, enablement: "disabled" } : srv);
      }
    }
  }

  return { instances, mcpServers, issues };
}
