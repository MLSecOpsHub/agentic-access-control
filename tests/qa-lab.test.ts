import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SCENARIO_BANNED_PHRASES } from "@/lib/scenario-catalog";
import { generateLab } from "../scripts/qa/lab";
import { verifyLab } from "../scripts/qa/verify";
import { labPaths, RECIPES, recipeDir } from "../scripts/qa/recipes";

// The QA lab must stay truthful: every recipe triggers exactly what its card
// promises (verify runs the real collectors on the isolated lab home), and the
// cards obey the scenario wording contract.

describe("QA lab", () => {
  let root: string;
  const env = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE, CODEX_HOME: process.env.CODEX_HOME };
  beforeAll(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-lab-"));
    await generateLab(root);
  });
  afterAll(async () => fs.rm(root, { recursive: true, force: true }));

  it("generates every recipe with a card and a git marker, plus the isolated home", async () => {
    const lab = labPaths(root);
    for (const r of RECIPES) {
      const dir = recipeDir(lab, r.id);
      expect((await fs.stat(path.join(dir, "QA.md"))).isFile(), r.id).toBe(true);
      expect((await fs.readFile(path.join(dir, ".git", "HEAD"), "utf8")).trim()).toBe("ref: refs/heads/main");
    }
    expect((await fs.stat(path.join(lab.home, ".claude.json"))).isFile()).toBe(true);
    expect((await fs.stat(path.join(lab.home, ".codex", "config.toml"))).isFile()).toBe(true);
  });

  it("every recipe's expectations hold against the real collectors (isolated home)", async () => {
    const { ok, lines } = await verifyLab(root);
    expect(ok, lines.filter((l) => l.startsWith("✗") || l.startsWith("—")).join("\n")).toBe(true);
    expect(process.env.HOME).toBe(env.HOME);
    expect(process.env.CODEX_HOME).toBe(env.CODEX_HOME);
    expect(process.env.USERPROFILE).toBe(env.USERPROFILE);
  });

  it("cards and the lab index obey the wording contract", async () => {
    const lab = labPaths(root);
    const texts = [await fs.readFile(path.join(lab.root, "README.md"), "utf8")];
    for (const r of RECIPES) texts.push(await fs.readFile(path.join(recipeDir(lab, r.id), "QA.md"), "utf8"));
    for (const t of texts) {
      const lower = t.toLowerCase();
      for (const phrase of SCENARIO_BANNED_PHRASES) expect(lower).not.toContain(phrase);
      expect(t).toContain("not observed enforcement or an observed attack");
    }
  });

  it("re-running the generator keeps files it does not own", async () => {
    const lab = labPaths(root);
    const stray = path.join(lab.home, ".claude", "credentials-like.json");
    await fs.writeFile(stray, "{}");
    await generateLab(root);
    expect((await fs.stat(stray)).isFile()).toBe(true);
    await generateLab(root, { reset: true });
    await expect(fs.stat(stray)).rejects.toThrow();
  });
});
