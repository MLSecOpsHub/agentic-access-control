import { promises as fs } from "fs";
import path from "path";
import { spawnSync } from "child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SnapshotSchema, type Severity } from "@/lib/schema";
import { runScenarios } from "@/lib/threat-scenarios";
import { SCENARIO_BANNED_PHRASES } from "@/lib/scenario-catalog";
import { buildJsonReport, buildSarif, meetsThreshold, summarize, worstSeverity } from "@/lib/report";
import { buildMachine, REPO_ROOT, rmMachine, SECRETS, type Machine } from "./helpers/machine";

async function fixture() {
  const raw = JSON.parse(await fs.readFile(path.join(REPO_ROOT, "data", "fixtures", "sample-snapshot.json"), "utf8"));
  const s = SnapshotSchema.parse(raw);
  return { s, scenarios: runScenarios({ instances: s.instances, mcpServers: s.mcpServers, findings: s.findings }) };
}

describe("report — thresholds", () => {
  it("orders severities and compares against a threshold", () => {
    expect(meetsThreshold("critical", "high")).toBe(true);
    expect(meetsThreshold("high", "high")).toBe(true);
    expect(meetsThreshold("medium", "high")).toBe(false);
    expect(meetsThreshold("info", "info")).toBe(true);
    expect(worstSeverity([], [])).toBeNull();
  });
});

describe("report — SARIF 2.1.0 from the fixture", () => {
  it("emits one result per finding and scenario, with rules, levels, locations and the caveat", async () => {
    const { s, scenarios } = await fixture();
    const sarif = buildSarif(s, scenarios, "0.0.0-test");
    expect(sarif.version).toBe("2.1.0");
    const run = sarif.runs[0];
    expect(run.results).toHaveLength(s.findings.length + scenarios.length);
    const ruleIds = new Set(run.tool.driver.rules.map((r) => r.id));
    for (const r of run.results) {
      expect(ruleIds.has(r.ruleId), r.ruleId).toBe(true);
      expect(["error", "warning", "note"]).toContain(r.level);
      expect(r.message.text.length).toBeGreaterThan(10);
    }
    const scenarioResults = run.results.filter((r) => r.properties.kind === "scenario");
    expect(scenarioResults.length).toBe(scenarios.length);
    for (const r of scenarioResults) {
      expect(r.message.text).toContain("not observed enforcement or an observed attack");
      expect(r.locations.length).toBeGreaterThan(0);
    }
    expect(run.tool.driver.fullDescription.text).toContain("not enforcement");
    expect(run.properties.snapshotHash).toBe(s.hash);
    const text = JSON.stringify(sarif).toLowerCase();
    for (const phrase of SCENARIO_BANNED_PHRASES) expect(text).not.toContain(phrase);
  });

  it("JSON report carries the summary, the full redacted snapshot and the caveat", async () => {
    const { s, scenarios } = await fixture();
    const report = buildJsonReport(s, scenarios, "0.0.0-test");
    expect(report.caveat).toContain("not enforcement");
    expect(report.summary.instances).toBe(s.instances.length);
    expect(report.summary.worstSeverity).toBe("critical");
    expect(report.snapshot.hash).toBe(s.hash);
    const sum = summarize(s, scenarios);
    expect(Object.values(sum.findings).reduce((a, b) => a + b, 0)).toBe(s.findings.length);
  });
});

describe("check CLI end to end on the fixture machine", () => {
  let m: Machine;
  beforeAll(async () => {
    m = await buildMachine();
  });
  afterAll(async () => rmMachine(m));

  function runCheck(args: string[]) {
    const tsxCli = path.join(REPO_ROOT, "node_modules", "tsx", "dist", "cli.mjs");
    return spawnSync(process.execPath, [tsxCli, path.join(REPO_ROOT, "collectors", "check.ts"), m.project, ...args], {
      cwd: m.workDir,
      env: { ...process.env, HOME: m.home },
      encoding: "utf8",
      timeout: 90_000,
    });
  }

  it("prints SARIF to stdout, writes exactly one snapshot, fails on findings at or above the threshold", async () => {
    const r = runCheck(["--format", "sarif", "--fail-on", "info"]);
    expect(r.status, r.stderr).toBe(1);
    const sarif = JSON.parse(r.stdout);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
    expect(r.stdout).not.toContain(SECRETS.github);
    expect(r.stderr).toContain("fail-on info: FAIL");
    const files = await fs.readdir(path.join(m.workDir, "data", "snapshots"));
    expect(files).toHaveLength(1);
  });

  it("passes when nothing meets the threshold and honours --no-write", async () => {
    const probe = runCheck(["--format", "json", "--no-write"]);
    expect(probe.status).toBe(0); // no --fail-on → never fails
    const worst = JSON.parse(probe.stdout).summary.worstSeverity as Severity | null;
    expect(worst).not.toBeNull();
    // Pick a threshold strictly above the worst severity present, if one exists.
    const ladder: Severity[] = ["critical", "high", "medium", "low", "info"];
    const above = ladder[ladder.indexOf(worst!) - 1];
    if (above) {
      const r = runCheck(["--fail-on", above, "--no-write"]);
      expect(r.status, r.stderr).toBe(0);
      expect(r.stderr).toContain(`fail-on ${above}: pass`);
    }
    const files = await fs.readdir(path.join(m.workDir, "data", "snapshots"));
    expect(files).toHaveLength(1); // still only the snapshot from the previous test
  });

  it("rejects bad options with exit 2", () => {
    expect(runCheck(["--format", "xml"]).status).toBe(2);
    expect(runCheck(["--fail-on", "severe"]).status).toBe(2);
  });
});
