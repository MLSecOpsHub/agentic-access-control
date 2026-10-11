export const TRACE_SCHEMA_VERSION: string;
export const TRACE_KINDS: string[];
export interface ProjectedTraceEvent {
  schemaVersion: string;
  platform: "claude-code" | "gemini-cli" | "codex-cli";
  sessionId: string | null;
  promptId: string | null;
  agentId: string | null;
  agentType: string | null;
  toolUseId: string | null;
  toolName: string | null;
  cwd: string | null;
  eventAt: string;
  platformVersion: string | null;
  kind: string;
  resource: string;
  detail: Record<string, string | number | boolean>;
  outcome: "ok" | "failed" | "denied" | "unknown";
}
export function relPath(p: unknown, cwd: unknown): string | null;
export function stripUrl(u: unknown): string | null;
export function splitMcpTool(name: unknown): { server: string; tool: string | null } | null;
export function projectHookPayload(payload: unknown, opts?: { reads?: boolean }): ProjectedTraceEvent | null;
