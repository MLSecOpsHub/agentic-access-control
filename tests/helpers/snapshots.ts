import { promises as fs } from "fs";
import path from "path";
import { SCHEMA_VERSION, type McpServer, type PermissionRule, type Snapshot } from "@/lib/schema";
import { snapshotHash } from "@/lib/hash";

// Programmatic snapshot factory for the SR5 and XSS suites: builds fully
// valid, correctly hashed snapshots so tests tamper from a known-good state.

export function makeRule(overrides: Partial<PermissionRule> = {}): PermissionRule {
  return {
    effect: "deny",
    matcher: "Read(./.env)",
    tool: "Read",
    sourceFile: "/tmp/fixture/.claude/settings.json",
    sourceLevel: "user",
    precedenceRank: 4, // effect-first: deny(0)*5 + user(4)
    ...overrides,
  };
}

export function makeServer(overrides: Partial<McpServer> = {}): McpServer {
  return {
    name: "github",
    transport: "stdio",
    commandOrUrl: "npx",
    args: ["-y", "@modelcontextprotocol/server-github"],
    envKeys: ["GITHUB_TOKEN"],
    declaredTools: null,
    enablement: null,
    sourceFile: "/tmp/fixture/.claude.json",
    instanceId: "claude-code:user",
    ...overrides,
  };
}

export function makeSnapshot(overrides: Partial<Snapshot> = {}): Snapshot {
  const snapshot: Snapshot = {
    schemaVersion: SCHEMA_VERSION,
    generatedAt: "2026-08-14T00:00:00.000Z",
    machineId: "fixture000001",
    hash: "",
    collectors: ["claude-code"],
    instances: [
      {
        id: "claude-code:user",
        platform: "claude-code",
        version: null,
        scope: "user",
        projectPath: null,
        configFiles: ["/tmp/fixture/.claude/settings.json"],
        defaultMode: "acceptEdits",
        defaultModeSourceFile: "/tmp/fixture/.claude/settings.json",
        permissionRules: [makeRule()],
        sandbox: null,
        hooks: [],
      },
    ],
    mcpServers: [makeServer()],
    findings: [],
    ...overrides,
  };
  snapshot.hash = snapshotHash(snapshot);
  return snapshot;
}

/** Write snapshots into <base>/data/snapshots with ISO-style names. */
export async function writeSnapshotDir(
  base: string,
  entries: Array<{ name: string; content: Snapshot | string }>,
): Promise<void> {
  const dir = path.join(base, "data", "snapshots");
  await fs.mkdir(dir, { recursive: true });
  for (const e of entries) {
    const text = typeof e.content === "string" ? e.content : JSON.stringify(e.content, null, 2);
    await fs.writeFile(path.join(dir, e.name), text);
  }
}
