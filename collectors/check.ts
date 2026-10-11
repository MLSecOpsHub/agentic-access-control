import { readFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { SeveritySchema, type Severity } from "../lib/schema";
import { runScenarios } from "../lib/threat-scenarios";
import { buildJsonReport, buildSarif, meetsThreshold, summarize } from "../lib/report";
import { collectSnapshot, writeSnapshot } from "./pipeline";

// Headless check for CI and scripts.
//   agentlens check [root ...] [--format json|sarif] [--fail-on <severity>] [--no-write]
// Collects exactly like `collect` (same read-only pipeline, same single
// snapshot write unless --no-write), prints the report to STDOUT, a one-line
// summary to STDERR, and exits 1 when any finding or scenario is at or above
// --fail-on. Exit 2 = usage or collection error. Nothing leaves the machine.

function usage(msg?: string): never {
  if (msg) console.error(`check: ${msg}`);
  console.error("usage: check [root ...] [--format json|sarif] [--fail-on critical|high|medium|low|info] [--no-write]");
  process.exit(2);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const roots: string[] = [];
  let format = "json";
  let failOn: string | null = null;
  let write = true;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--format") format = argv[++i] ?? "";
    else if (a.startsWith("--format=")) format = a.slice("--format=".length);
    else if (a === "--fail-on") failOn = argv[++i] ?? "";
    else if (a.startsWith("--fail-on=")) failOn = a.slice("--fail-on=".length);
    else if (a === "--no-write") write = false;
    else if (a.startsWith("-")) usage(`unknown option ${a}`);
    else roots.push(a);
  }
  if (format !== "json" && format !== "sarif") usage(`--format must be json or sarif`);
  const threshold: Severity | null = failOn === null ? null : (() => {
    const parsed = SeveritySchema.safeParse(failOn);
    if (!parsed.success) usage(`--fail-on must be one of ${SeveritySchema.options.join("|")}`);
    return parsed.data;
  })();

  const version = (JSON.parse(
    readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8"),
  ) as { version: string }).version;

  const { snapshot } = await collectSnapshot(roots);
  const file = write ? await writeSnapshot(snapshot) : null;
  const scenarios = runScenarios({
    instances: snapshot.instances,
    mcpServers: snapshot.mcpServers,
    findings: snapshot.findings,
  });

  const report = format === "sarif" ? buildSarif(snapshot, scenarios, version) : buildJsonReport(snapshot, scenarios, version);
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");

  const s = summarize(snapshot, scenarios);
  const worst = s.worstSeverity ?? "none";
  const failing =
    threshold !== null &&
    [...snapshot.findings, ...scenarios].some((x) => meetsThreshold(x.severity, threshold));
  console.error(
    `agentlens check: ${s.instances} instances · ${s.mcpServers} servers · ${snapshot.findings.length} findings · ${scenarios.length} scenarios · worst ${worst}` +
      (file ? ` · snapshot ${file}` : "") +
      (threshold ? ` · fail-on ${threshold}: ${failing ? "FAIL" : "pass"}` : ""),
  );
  process.exitCode = failing ? 1 : 0;
}

main().catch((err) => {
  console.error("check failed:", err instanceof Error ? err.message : String(err));
  process.exitCode = 2;
});
