import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { collectSnapshot } from "../../collectors/pipeline";
import { runScenarios } from "../../lib/threat-scenarios";
import type { Severity } from "../../lib/schema";
import { generateLab } from "./lab";
import { labPaths, RECIPES, recipeDir, USER_TIER_INSTANCE_IDS, type Expect } from "./recipes";

// Deterministic self-check: generate a lab (into a fresh temp dir unless a lab
// dir is given), collect it with the ISOLATED home, and assert every recipe's
// expectations. Nothing is written to any data dir — the snapshot stays in
// memory.

export interface VerifyResult {
  ok: boolean;
  lines: string[];
}

function parseMust(entry: string): { id: string; severity: Severity | null } {
  const [id, sev] = entry.split(":");
  return { id, severity: (sev as Severity | undefined) ?? null };
}

export async function verifyLab(labDir?: string): Promise<VerifyResult> {
  const temp = labDir ? null : await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-qa-"));
  const root = labDir ?? temp!;
  await generateLab(root, { reset: !labDir });
  const lab = labPaths(root);

  const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE, CODEX_HOME: process.env.CODEX_HOME };
  process.env.HOME = lab.home;
  process.env.USERPROFILE = lab.home;
  process.env.CODEX_HOME = lab.codexHome;
  const lines: string[] = [];
  let ok = true;
  const check = (cond: boolean, text: string) => {
    ok = ok && cond;
    lines.push(`${cond ? "✓" : "✗"} ${text}`);
  };

  try {
    const { snapshot } = await collectSnapshot(RECIPES.map((r) => recipeDir(lab, r.id)));
    const scenarios = runScenarios({ instances: snapshot.instances, mcpServers: snapshot.mcpServers, findings: snapshot.findings });

    for (const r of RECIPES) {
      const dir = recipeDir(lab, r.id);
      const insts = snapshot.instances.filter((i) => i.projectPath === dir);
      const ids = new Set(insts.map((i) => i.id));
      const findings = snapshot.findings.filter((f) => f.instanceId !== null && ids.has(f.instanceId));
      const scen = scenarios.filter((s) => ids.has(s.instanceId));
      const e: Expect = r.expect;
      lines.push(`— ${r.id}`);
      check(insts.length === (e.instances ?? 1), `  ${e.instances ?? 1} instance(s) for ${r.id} (got ${insts.length})`);

      const needed = new Map<string, number>();
      for (const m of e.must) needed.set(m, (needed.get(m) ?? 0) + 1);
      for (const [entry, n] of needed) {
        const { id, severity } = parseMust(entry);
        const got = findings.filter((f) => f.heuristicId === id && (severity === null || f.severity === severity)).length;
        check(got >= n, `  ${entry}${n > 1 ? ` ×${n}` : ""} present (got ${got})`);
      }
      for (const id of e.mustNot) {
        const got = findings.filter((f) => f.heuristicId === id).length;
        check(got === 0, `  ${id} absent${got > 0 ? ` (got ${got})` : ""}`);
      }
      for (const [id, sev] of Object.entries(e.scenarios)) {
        const got = scen.filter((s) => s.scenarioId === id);
        check(got.length === 1 && got[0].severity === sev, `  ${id} ${sev}${got.length ? ` (got ${got.map((s) => s.severity).join(",")})` : " (missing)"}`);
      }
      const unexpected = scen.filter((s) => !(s.scenarioId in e.scenarios)).map((s) => s.scenarioId);
      check(unexpected.length === 0, `  no other scenario${unexpected.length ? ` (got ${unexpected.join(", ")})` : ""}`);
      for (const n of e.notes ?? []) {
        check(insts.some((i) => i.notes.some((x) => x.includes(n))), `  note contains “${n}”`);
      }
    }

    lines.push("— user tier (isolated home)");
    for (const id of USER_TIER_INSTANCE_IDS) {
      const inst = snapshot.instances.find((i) => i.id === id);
      const findings = snapshot.findings.filter((f) => f.instanceId === id).length;
      const scen = scenarios.filter((s) => s.instanceId === id).length;
      check(!!inst && findings === 0 && scen === 0, `  ${id} present and clean (${findings} findings, ${scen} scenarios)`);
    }
    const parse = snapshot.findings.filter((f) => f.heuristicId === "PARSE").length;
    check(parse === 0, `  no PARSE findings anywhere (got ${parse})`);
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    if (temp) await fs.rm(temp, { recursive: true, force: true });
  }
  return { ok, lines };
}
