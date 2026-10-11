import { collectSnapshot, writeSnapshot } from "./pipeline";

// Snapshot CLI. Usage: npm run collect [-- <project-root> ...]
//   No roots given → cwd plus every directory listed under `projects` in
//   ~/.claude.json (where Claude Code has been launched from). Passing explicit
//   roots disables that discovery. Pipeline and the single write: ./pipeline.ts.

async function main(): Promise<void> {
  const explicit = process.argv.slice(2).filter((a) => !a.startsWith("-"));
  const { snapshot, roots, discovered, issues } = await collectSnapshot(explicit);
  const file = await writeSnapshot(snapshot);

  console.log(`AgentLens snapshot written: ${file}`);
  console.log(
    `  project roots scanned: ${roots.length}${
      discovered.length > 0 ? ` (${discovered.length} discovered from ~/.claude.json projects)` : ""
    }`,
  );
  console.log(
    `  instances: ${snapshot.instances.length} · mcp servers: ${snapshot.mcpServers.length} · findings: ${snapshot.findings.length} (${issues.length} parse notes)`,
  );
}

main().catch((err) => {
  console.error("collect failed:", err);
  process.exitCode = 1;
});
