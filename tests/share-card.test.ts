import { promises as fs } from "fs";
import path from "path";
import { describe, expect, it } from "vitest";
import { SnapshotSchema } from "@/lib/schema";
import { runScenarios } from "@/lib/threat-scenarios";
import { SCENARIO_BANNED_PHRASES } from "@/lib/scenario-catalog";
import { buildShareCard, SHARE_CARD_REPO } from "@/lib/share-card";
import { REPO_ROOT } from "./helpers/machine";

// The share card is the one artifact designed to leave the machine, so it is
// held to a disclosure contract: aggregates only. Every identifying string in
// the fixture must be absent from the card text.

describe("share card — counts only, nothing identifying", () => {
  it("contains no path, matcher, server name, hostname, machine id, or evidence from the snapshot", async () => {
    const raw = JSON.parse(
      await fs.readFile(path.join(REPO_ROOT, "data", "fixtures", "sample-snapshot.json"), "utf8"),
    );
    const s = SnapshotSchema.parse(raw);
    const scenarios = runScenarios({ instances: s.instances, mcpServers: s.mcpServers, findings: s.findings });
    const card = buildShareCard(s, scenarios);
    const body = card.replace(SHARE_CARD_REPO, ""); // the repo URL legitimately contains "github"

    const identifying = new Set<string>([s.machineId]);
    for (const i of s.instances) {
      if (i.projectPath) identifying.add(i.projectPath);
      for (const f of i.configFiles) identifying.add(f);
      for (const r of i.permissionRules) { identifying.add(r.matcher); identifying.add(r.sourceFile); }
      for (const h of i.hooks) { identifying.add(h.commandPreview); identifying.add(h.sourceFile); }
      for (const n of i.notes) identifying.add(n);
    }
    for (const m of s.mcpServers) {
      identifying.add(m.name); identifying.add(m.commandOrUrl); identifying.add(m.sourceFile);
      for (const a of m.args) identifying.add(a);
      for (const k of m.envKeys) identifying.add(k);
    }
    for (const f of s.findings) { identifying.add(f.title); identifying.add(f.evidence); }
    for (const sc of scenarios) for (const p of sc.preconditions) { identifying.add(p.claim); identifying.add(p.evidence); }

    expect(identifying.size).toBeGreaterThan(20);
    for (const v of identifying) {
      if (v.length < 3) continue; // "-y" style args are not identifying
      expect(body, `card leaks "${v}"`).not.toContain(v);
    }
  });

  it("reports the aggregate counts and obeys the wording contract", async () => {
    const raw = JSON.parse(
      await fs.readFile(path.join(REPO_ROOT, "data", "fixtures", "sample-snapshot.json"), "utf8"),
    );
    const s = SnapshotSchema.parse(raw);
    const scenarios = runScenarios({ instances: s.instances, mcpServers: s.mcpServers, findings: s.findings });
    const card = buildShareCard(s, scenarios);
    expect(card).toContain(`Agent instances: ${s.instances.length}`);
    expect(card).toContain(`Risk findings: ${s.findings.length}`);
    expect(card).toContain(`Threat scenarios: ${scenarios.length}`);
    expect(card).toContain("not enforcement, not observed activity");
    for (const phrase of SCENARIO_BANNED_PHRASES) expect(card.toLowerCase()).not.toContain(phrase);
  });
});
