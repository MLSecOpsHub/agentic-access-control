import { promises as fs } from "fs";
import path from "path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { collectClaudeCode } from "@/collectors/claude-code";
import { buildMachine, rmMachine, SECRETS, type Machine } from "./helpers/machine";

// Trust state and legacy grants recorded outside settings files — previously a
// declared non-guarantee (security-architecture §5.1), now collected as notes.

describe("Claude Code folder trust and legacy allowedTools from ~/.claude.json", () => {
  let m: Machine;
  const prevHome = process.env.HOME;
  beforeAll(async () => {
    m = await buildMachine();
    process.env.HOME = m.home;
  });
  afterAll(async () => {
    process.env.HOME = prevHome;
    await rmMachine(m);
  });

  async function withProjectEntry(entry: Record<string, unknown>) {
    await fs.writeFile(path.join(m.home, ".claude.json"), JSON.stringify({ projects: { [m.project]: entry } }));
    const { instances } = await collectClaudeCode([m.project]);
    return instances.find((i) => i.scope === "project")!;
  }

  it("records an accepted trust dialog", async () => {
    const inst = await withProjectEntry({ hasTrustDialogAccepted: true });
    expect(inst.notes.some((n) => n.startsWith("Folder trust: accepted"))).toBe(true);
    expect(inst.notes.some((n) => n.includes("allowedTools"))).toBe(false);
  });

  it("records a declined trust dialog and legacy allowedTools with redaction", async () => {
    const inst = await withProjectEntry({
      hasTrustDialogAccepted: false,
      allowedTools: ["Bash(npm test)", `Bash(curl -H 'Authorization: Bearer ${SECRETS.bearerToken}')`],
      lastCost: 12.34, // usage telemetry must never surface
    });
    expect(inst.notes.some((n) => n.startsWith("Folder trust: not accepted"))).toBe(true);
    const legacy = inst.notes.find((n) => n.includes("Legacy per-project allowedTools"))!;
    expect(legacy).toContain("(2)");
    expect(legacy).toContain("Bash(npm test)");
    expect(legacy).not.toContain(SECRETS.bearerToken);
    expect(JSON.stringify(inst)).not.toContain("12.34");
    // legacy grants are notes, not declarations
    expect(inst.permissionRules.some((r) => r.matcher === "Bash(npm test)")).toBe(false);
  });

  it("states when no trust decision is recorded", async () => {
    const inst = await withProjectEntry({ mcpServers: {} });
    expect(inst.notes.some((n) => n.startsWith("Folder trust: no recorded decision"))).toBe(true);
  });
});
