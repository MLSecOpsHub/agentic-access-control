import { z } from "zod";

// Canonical data model — semantics documented in docs/data-model.md.
// This file is authoritative when the two diverge.

export const EffectSchema = z.enum(["allow", "ask", "deny"]);
export type Effect = z.infer<typeof EffectSchema>;

export const SourceLevelSchema = z.enum(["managed", "user", "project", "local", "flag"]);
export type SourceLevel = z.infer<typeof SourceLevelSchema>;

export const PermissionRuleSchema = z.object({
  effect: EffectSchema,
  matcher: z.string(),
  tool: z.string().nullable(),
  sourceFile: z.string(),
  sourceLevel: SourceLevelSchema,
  precedenceRank: z.number(),
});
export type PermissionRule = z.infer<typeof PermissionRuleSchema>;

export const SandboxConfigSchema = z.object({
  enabled: z.boolean().nullable(),
  allowUnsandboxedCommands: z.boolean().nullable(),
  networkAllowlist: z.array(z.string()),
  notes: z.string().nullable(),
});
export type SandboxConfig = z.infer<typeof SandboxConfigSchema>;

export const HookSchema = z.object({
  event: z.string(),
  matcher: z.string().nullable(),
  // Redacted and truncated at collection time (SR2) — hooks are arbitrary shell.
  commandPreview: z.string(),
  sourceFile: z.string(),
});
export type Hook = z.infer<typeof HookSchema>;

export const PlatformSchema = z.enum(["claude-code", "codex-cli", "gemini-cli", "generic-mcp"]);
export type Platform = z.infer<typeof PlatformSchema>;

export const AgentInstanceSchema = z.object({
  id: z.string(),
  platform: PlatformSchema,
  version: z.string().nullable(),
  scope: z.enum(["user", "project"]),
  projectPath: z.string().nullable(),
  configFiles: z.array(z.string()),
  defaultMode: z.string().nullable(),
  permissionRules: z.array(PermissionRuleSchema),
  sandbox: SandboxConfigSchema.nullable(),
  hooks: z.array(HookSchema),
});
export type AgentInstance = z.infer<typeof AgentInstanceSchema>;

export const McpServerSchema = z.object({
  name: z.string(),
  transport: z.enum(["stdio", "http", "sse", "unknown"]),
  commandOrUrl: z.string(),
  args: z.array(z.string()),
  // Names only — values are dropped unconditionally at collection time (SR2).
  envKeys: z.array(z.string()),
  declaredTools: z.array(z.string()).nullable(),
  sourceFile: z.string(),
  instanceId: z.string(),
});
export type McpServer = z.infer<typeof McpServerSchema>;

export const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
export type Severity = z.infer<typeof SeveritySchema>;

export const RiskFindingSchema = z.object({
  id: z.string(),
  // "H5" is retired (asserted the opposite of documented deny-first semantics)
  // but stays in the enum so snapshots collected before its removal still parse.
  heuristicId: z.enum(["H1", "H2", "H3", "H4", "H5", "H6", "H7", "PARSE"]),
  severity: SeveritySchema,
  title: z.string(),
  evidence: z.string(),
  instanceId: z.string().nullable(),
  sourceFile: z.string().nullable(),
});
export type RiskFinding = z.infer<typeof RiskFindingSchema>;

export const SnapshotSchema = z.object({
  schemaVersion: z.string(),
  generatedAt: z.string(),
  machineId: z.string(),
  // SHA-256 of the canonicalized snapshot body excluding this field (SR5).
  hash: z.string(),
  collectors: z.array(z.string()),
  instances: z.array(AgentInstanceSchema),
  mcpServers: z.array(McpServerSchema),
  findings: z.array(RiskFindingSchema),
});
export type Snapshot = z.infer<typeof SnapshotSchema>;

export const SCHEMA_VERSION = "0.1.0";
