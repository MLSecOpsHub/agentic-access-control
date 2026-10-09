import path from "path";
import type { AgentInstance, McpServer } from "../lib/schema";
import { redact } from "../lib/redact";
import { asStringArray, findFilesNamed, hash8, readJsonConfig, type ParseIssue } from "./util";
import type { CollectorResult } from "./claude-code";

// Generic MCP collector — spec: docs/collectors.md §5.
// Picks up editor-agnostic MCP manifests (mcp.json, .vscode/mcp.json,
// .cursor/mcp.json). Claude's project-level `.mcp.json` is claimed by the
// claude-code collector, so it is intentionally NOT in this name set.

const NAMES = new Set(["mcp.json"]);

export async function collectGenericMcp(projectRoots: string[]): Promise<CollectorResult> {
  const issues: ParseIssue[] = [];
  const instances: AgentInstance[] = [];
  const mcpServers: McpServer[] = [];

  for (const root of projectRoots) {
    const abs = path.resolve(root);
    const files = await findFilesNamed(abs, NAMES);
    for (const file of files) {
      const data = await readJsonConfig(file, issues);
      if (!data) continue;
      const block = (data.mcpServers ?? data.servers) as Record<string, unknown> | undefined;
      if (typeof block !== "object" || block === null) continue;

      const id = `generic-mcp:project:${hash8(file)}`;
      instances.push({
        id,
        platform: "generic-mcp",
        version: null,
        scope: "project",
        projectPath: abs,
        configFiles: [file],
        defaultMode: null,
        defaultModeSourceFile: null,
        permissionRules: [],
        sandbox: null,
        hooks: [],
        notes: [],
      });

      for (const [name, cfgRaw] of Object.entries(block)) {
        if (typeof cfgRaw !== "object" || cfgRaw === null) continue;
        const cfg = cfgRaw as Record<string, unknown>;
        const url = typeof cfg.url === "string" ? cfg.url : null;
        const command = typeof cfg.command === "string" ? cfg.command : null;
        mcpServers.push({
          name: redact(name),
          transport: cfg.type === "sse" ? "sse" : url ? "http" : command ? "stdio" : "unknown",
          commandOrUrl: redact(url ?? command ?? ""),
          args: asStringArray(cfg.args).map(redact),
          envKeys: typeof cfg.env === "object" && cfg.env !== null ? Object.keys(cfg.env) : [],
          declaredTools: null,
          enablement: null, // generic manifests carry no Claude-style approval state
          sourceFile: file,
          instanceId: id,
        });
      }
    }
  }

  return { instances, mcpServers, issues };
}
