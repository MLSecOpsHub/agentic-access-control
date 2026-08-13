import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { createHash } from "crypto";
import { SCHEMA_VERSION, SnapshotSchema, type RiskFinding, type Snapshot } from "../lib/schema";
import { runHeuristics } from "../lib/heuristics";
import { snapshotHash } from "../lib/hash";
import { collectClaudeCode } from "./claude-code";
import { collectGenericMcp } from "./generic-mcp";
import { collectCodexCli } from "./codex-cli";
import { collectGeminiCli } from "./gemini-cli";
import { PARSE_ISSUE_TEXT, type ParseIssue } from "./util";

// Snapshot orchestrator. SR1: this file owns the pipeline's ONLY write, and it
// targets data/snapshots/ exclusively.
//
// Usage: npm run collect [-- <project-root> ...]   (default root: cwd)

const OUT_DIR = path.join(process.cwd(), "data", "snapshots");

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

async function main(): Promise<void> {
  const roots = process.argv.slice(2).filter((a) => !a.startsWith("-"));
  if (roots.length === 0) roots.push(process.cwd());

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

  SnapshotSchema.parse(snapshot); // never write an invalid snapshot

  await fs.mkdir(OUT_DIR, { recursive: true });
  const file = path.join(OUT_DIR, `${snapshot.generatedAt.replace(/[:.]/g, "-")}.json`);
  await fs.writeFile(file, JSON.stringify(snapshot, null, 2), { flag: "wx" }); // wx: never overwrite

  console.log(`AgentLens snapshot written: ${file}`);
  console.log(
    `  instances: ${instances.length} · mcp servers: ${mcpServers.length} · findings: ${findings.length} (${issues.length} parse notes)`,
  );
}

main().catch((err) => {
  console.error("collect failed:", err);
  process.exitCode = 1;
});
