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
// Precedence interpretation (SR4 — ours, not ground truth):
//   level: managed > local > project > user; within a level: deny > ask > allow.

const LEVEL_RANK: Record<SourceLevel, number> = { managed: 0, local: 1, project: 2, user: 3, flag: 4 };
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

function parseTool(matcher: string): string | null {
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
        precedenceRank: LEVEL_RANK[sf.level] * 3 + EFFECT_RANK[effect],
      });
    }
  }
  return rules;
}

function hooksFrom(sf: SettingsFile): Hook[] {
  const hooks = sf.data.hooks;
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
          out.push({ event, matcher, commandPreview: truncate(redact(cmd)), sourceFile: sf.file });
        }
      }
    }
  }
  return out;
}

function sandboxFrom(files: SettingsFile[]): SandboxConfig | null {
  for (const sf of files) {
    const sb = sf.data.sandbox;
    if (typeof sb !== "object" || sb === null) continue;
    const s = sb as Record<string, unknown>;
    const network = (s.network ?? {}) as Record<string, unknown>;
    const allowlist = [
      ...asStringArray(network.allowedDomains),
      ...asStringArray(network.allowedHosts),
      ...asStringArray(s.allowedDomains),
    ].map(redact);
    return {
      enabled: typeof s.enabled === "boolean" ? s.enabled : null,
      allowUnsandboxedCommands:
        typeof s.allowUnsandboxedCommands === "boolean" ? s.allowUnsandboxedCommands : null,
      networkAllowlist: allowlist,
      notes: "Egress filtering is hostname-only per vendor docs (TLS-blind; see landscape §1)",
    };
  }
  return null;
}

function defaultModeFrom(files: SettingsFile[]): string | null {
  // First hit in precedence order wins — `files` arrives sorted by level rank.
  for (const sf of files) {
    const perms = (sf.data.permissions ?? {}) as Record<string, unknown>;
    if (typeof perms.defaultMode === "string") return redact(perms.defaultMode);
  }
  return null;
}

function mcpServersFrom(
  data: Record<string, unknown>,
  sourceFile: string,
  instanceId: string,
): McpServer[] {
  const block = data.mcpServers;
  if (typeof block !== "object" || block === null) return [];
  const out: McpServer[] = [];
  for (const [name, cfgRaw] of Object.entries(block as Record<string, unknown>)) {
    if (typeof cfgRaw !== "object" || cfgRaw === null) continue;
    const cfg = cfgRaw as Record<string, unknown>;
    const url = typeof cfg.url === "string" ? cfg.url : null;
    const command = typeof cfg.command === "string" ? cfg.command : null;
    const declaredType = typeof cfg.type === "string" ? cfg.type : null;
    const transport: McpServer["transport"] =
      declaredType === "sse" ? "sse" : url ? "http" : command ? "stdio" : "unknown";
    out.push({
      name: redact(name),
      transport,
      commandOrUrl: redact(url ?? command ?? ""),
      args: asStringArray(cfg.args).map(redact),
      // SR2: env VALUES are dropped unconditionally — key names only.
      envKeys: typeof cfg.env === "object" && cfg.env !== null ? Object.keys(cfg.env) : [],
      declaredTools: null, // never obtained by executing the server (SR1)
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

  // ~/.claude.json carries user-level MCP server registrations.
  const claudeJsonPath = path.join(home, ".claude.json");
  const claudeJson = await readJsonConfig(claudeJsonPath, issues);

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
    defaultMode: defaultModeFrom(userSettings),
    permissionRules: userSettings.flatMap(rulesFrom),
    sandbox: sandboxFrom(userSettings),
    hooks: userSettings.flatMap(hooksFrom),
  };
  if (userInstance.configFiles.length > 0) {
    instances.push(userInstance);
    if (claudeJson) {
      mcpServers.push(...mcpServersFrom(claudeJson, claudeJsonPath, userInstance.id));
    }
  }

  for (const root of projectRoots) {
    const abs = path.resolve(root);
    const projCandidates = [
      ...userCandidates,
      { file: path.join(abs, ".claude", "settings.local.json"), level: "local" as const },
      { file: path.join(abs, ".claude", "settings.json"), level: "project" as const },
    ];
    const settings = await loadSettings(projCandidates, issues);
    const mcpJsonPath = path.join(abs, ".mcp.json");
    const mcpJson = await readJsonConfig(mcpJsonPath, issues);

    const hasProjectConfig = settings.some((s) => s.level === "project" || s.level === "local") || !!mcpJson;
    if (!hasProjectConfig) continue;

    const id = `claude-code:project:${hash8(abs)}`;
    instances.push({
      id,
      platform: "claude-code",
      version: null,
      scope: "project",
      projectPath: abs,
      configFiles: [...settings.map((s) => s.file), ...(mcpJson ? [mcpJsonPath] : [])],
      defaultMode: defaultModeFrom(settings),
      // Full effective set (managed+user+local+project), not just project-file rules.
      permissionRules: settings.flatMap(rulesFrom),
      sandbox: sandboxFrom(settings),
      hooks: settings.flatMap(hooksFrom),
    });
    if (mcpJson) mcpServers.push(...mcpServersFrom(mcpJson, mcpJsonPath, id));
  }

  return { instances, mcpServers, issues };
}
