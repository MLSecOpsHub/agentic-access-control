import { promises as fs } from "fs";
import os from "os";
import path from "path";
import type {
  AgentInstance,
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

function sandboxFrom(files: SettingsFile[]): SandboxConfig | null {
  // Per-field tier merge (Step 5): each field is taken independently from the
  // highest-precedence file that defines it — `files` arrives sorted by level
  // rank. Provenance per field lands in fieldSources for H6 attribution.
  let found = false;
  let enabled: boolean | null = null;
  let allowUnsandboxedCommands: boolean | null = null;
  let networkAllowlist: string[] = [];
  const fieldSources: Record<string, string> = {};

  for (const sf of files) {
    const sb = sf.data.sandbox;
    if (typeof sb !== "object" || sb === null) continue;
    found = true;
    const s = sb as Record<string, unknown>;
    if (enabled === null && typeof s.enabled === "boolean") {
      enabled = s.enabled;
      fieldSources.enabled = sf.file;
    }
    if (allowUnsandboxedCommands === null && typeof s.allowUnsandboxedCommands === "boolean") {
      allowUnsandboxedCommands = s.allowUnsandboxedCommands;
      fieldSources.allowUnsandboxedCommands = sf.file;
    }
    const network = (s.network ?? {}) as Record<string, unknown>;
    const allowlist = [
      ...asStringArray(network.allowedDomains),
      ...asStringArray(network.allowedHosts),
      ...asStringArray(s.allowedDomains),
    ].map(redact);
    if (!("networkAllowlist" in fieldSources) && allowlist.length > 0) {
      networkAllowlist = allowlist;
      fieldSources.networkAllowlist = sf.file;
    }
  }

  if (!found) return null;
  return {
    enabled,
    allowUnsandboxedCommands,
    networkAllowlist,
    notes: "Egress filtering is hostname-only per vendor docs (TLS-blind; see landscape §1)",
    fieldSources,
  };
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
    sandbox: sandboxFrom(userSettings),
    hooks: userSettings.flatMap(hooksFrom),
    notes: [],
  };
  if (userInstance.configFiles.length > 0) {
    instances.push(userInstance);
    if (claudeJson) {
      mcpServers.push(...mcpServersFrom(claudeJson, claudeJsonPath, userInstance.id));
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
      sandbox: sandboxFrom(settings),
      hooks: settings.flatMap(hooksFrom),
      notes: [],
    });

    if (mcpJson) {
      // Approval state for .mcp.json-declared servers is recorded in the
      // matching ~/.claude.json project entry. Disabled wins on conflict
      // (conservative). Null = no recorded choice — NOT "active" (SR4).
      const enabledNames = new Set(
        entries.flatMap((e) => asStringArray(e.enabledMcpjsonServers)).map(redact),
      );
      const disabledNames = new Set(
        entries.flatMap((e) => asStringArray(e.disabledMcpjsonServers)).map(redact),
      );
      for (const srv of mcpServersFrom(mcpJson, mcpJsonPath, id)) {
        const enablement = disabledNames.has(srv.name)
          ? "disabled"
          : enabledNames.has(srv.name)
            ? "enabled"
            : null;
        mcpServers.push({ ...srv, enablement });
      }
    }
    // Project-scoped MCP servers registered directly in ~/.claude.json.
    for (const entry of entries) {
      mcpServers.push(...mcpServersFrom(entry, claudeJsonPath, id));
    }
  }

  return { instances, mcpServers, issues };
}
