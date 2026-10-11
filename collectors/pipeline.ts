import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { createHash } from "crypto";
import { SCHEMA_VERSION, SnapshotSchema, type RiskFinding, type Snapshot } from "../lib/schema";
import { runHeuristics } from "../lib/heuristics";
import { snapshotHash } from "../lib/hash";
import { collectClaudeCode, discoverProjectRoots } from "./claude-code";
import { collectGenericMcp } from "./generic-mcp";
import { collectCodexCli } from "./codex-cli";
import { collectGeminiCli } from "./gemini-cli";
import { PARSE_ISSUE_TEXT, type ParseIssue } from "./util";

// The collection pipeline shared by `collect`, `check` and `watch`. SR1: the
// collector tree performs exactly two kinds of filesystem mutation, both on
// AgentLens's own data directory (AGENTLENS_DATA_DIR or <cwd>/data) and never
// on agent configuration: `writeSnapshot` (the only write) and
// `pruneSnapshots` (the only deletion — opt-in via `watch --keep`, restricted
// to snapshot files this pipeline named).

export const OUT_DIR = path.join(
  process.env.AGENTLENS_DATA_DIR ?? path.join(process.cwd(), "data"),
  "snapshots",
);

export interface CollectRun {
  snapshot: Snapshot;
  roots: string[];
  discovered: string[];
  issues: ParseIssue[];
}

function issueFindings(issues: ParseIssue[]): RiskFinding[] {
  return issues.map((issue, i) => ({
    id: `PARSE:global:${i}`,
    heuristicId: "PARSE" as const,
    severity: "info" as const,
    title: `Config not fully readable: ${path.basename(issue.file)}`,
    // SR2: fixed code + canned text only — no exception content (F3 fix)
    evidence: `${issue.code}: ${PARSE_ISSUE_TEXT[issue.code]}`,
    instanceId: null,
    sourceFile: issue.file,
  }));
}

// No explicit roots → cwd plus every directory listed under `projects` in
// ~/.claude.json (where Claude Code has been launched from). Explicit roots
// disable that discovery.
export async function collectSnapshot(explicitRoots: string[]): Promise<CollectRun> {
  const discovered = explicitRoots.length === 0 ? await discoverProjectRoots() : [];
  const roots = explicitRoots.length > 0 ? explicitRoots : [process.cwd(), ...discovered];

  const results = [
    await collectClaudeCode(roots),
    await collectGenericMcp(roots),
    await collectCodexCli(roots),
    await collectGeminiCli(roots),
  ];

  const instances = results.flatMap((r) => r.instances);
  const mcpServers = results.flatMap((r) => r.mcpServers);
  const issues = results.flatMap((r) => r.issues);
  const findings = [...runHeuristics({ instances, mcpServers }), ...issueFindings(issues)];

  const snapshot: Snapshot = {
    schemaVersion: SCHEMA_VERSION,
    generatedAt: new Date().toISOString(),
    machineId: createHash("sha256").update(os.hostname()).digest("hex").slice(0, 12),
    hash: "",
    collectors: ["claude-code", "generic-mcp", "codex-cli", "gemini-cli"],
    instances,
    mcpServers,
    findings,
  };
  snapshot.hash = snapshotHash(snapshot); // SR5 — set last, see lib/hash.ts
  SnapshotSchema.parse(snapshot); // never emit an invalid snapshot

  return { snapshot, roots, discovered, issues };
}

// Files this pipeline writes: <ISO timestamp with : and . replaced by ->.json
const SNAPSHOT_NAME = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z\.json$/;

/** Delete the oldest snapshot files beyond `keep` (never fewer than 2 — drift needs two). */
export async function pruneSnapshots(outDir: string, keep: number): Promise<string[]> {
  const retain = Math.max(2, Math.floor(keep));
  let names: string[];
  try {
    names = (await fs.readdir(outDir)).filter((f) => SNAPSHOT_NAME.test(f)).sort();
  } catch {
    return [];
  }
  const removed: string[] = [];
  for (const f of names.slice(0, Math.max(0, names.length - retain))) {
    const file = path.join(outDir, f);
    await fs.unlink(file);
    removed.push(file);
  }
  return removed;
}

export async function writeSnapshot(snapshot: Snapshot, outDir = OUT_DIR): Promise<string> {
  await fs.mkdir(outDir, { recursive: true });
  const file = path.join(outDir, `${snapshot.generatedAt.replace(/[:.]/g, "-")}.json`);
  await fs.writeFile(file, JSON.stringify(snapshot, null, 2), { flag: "wx" }); // wx: never overwrite
  return file;
}
