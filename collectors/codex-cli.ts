import type { CollectorResult } from "./claude-code";

// Codex CLI collector — STUB. Spec: docs/collectors.md §3.
// TODO(v1.5):
//  - Parse ~/.codex/config.toml (needs a TOML parser dependency — review T10
//    before adding) and project requirements.toml.
//  - Map approval policy → coarse rules; `danger-full-access` → H1 via
//    defaultMode passthrough; sandbox mode + network allowlist → SandboxConfig.
//  - MCP servers from `mcp_servers` tables.
export async function collectCodexCli(_projectRoots: string[]): Promise<CollectorResult> {
  return { instances: [], mcpServers: [], issues: [] };
}
