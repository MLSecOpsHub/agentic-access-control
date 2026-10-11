import { promises as fs } from "fs";
import path from "path";
import {
  homeFiles,
  labPaths,
  LIVE_CAVEAT,
  RECIPES,
  recipeDir,
  SR4_LINE,
  type LabPaths,
  type Recipe,
} from "./recipes";

// Lab generator: materialises recipes under <lab>/projects/<id>/ and the
// isolated HOME under <lab>/home/. It writes ONLY the paths it owns (recorded
// in lab.json) so credentials or edits you add survive a re-run; --reset wipes
// projects/ and home/ (never data/).

export interface LabManifest {
  generatedAt: string;
  lab: LabPaths;
  recipes: string[];
  owned: string[];
}

const serialize = (v: string | object) => (typeof v === "string" ? v : JSON.stringify(v, null, 2) + "\n");

async function writeOwned(file: string, content: string, owned: string[]) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, content);
  owned.push(file);
}

// A minimal valid empty repository so the Claude Code collector's git-root
// walk-up stops here instead of at the AgentLens repo (and so Claude Code
// treats each recipe as its own project).
async function writeGitMarker(dir: string, owned: string[]) {
  await fs.mkdir(path.join(dir, ".git", "objects"), { recursive: true });
  await fs.mkdir(path.join(dir, ".git", "refs"), { recursive: true });
  await writeOwned(path.join(dir, ".git", "HEAD"), "ref: refs/heads/main\n", owned);
}

export function renderCard(r: Recipe, lab: LabPaths): string {
  const dir = recipeDir(lab, r.id);
  const must = r.expect.must.length > 0 ? r.expect.must.join(", ") : "none";
  const scenarios =
    Object.keys(r.expect.scenarios).length > 0
      ? Object.entries(r.expect.scenarios)
          .map(([id, sev]) => `${id} (${sev})`)
          .join(", ")
      : "none";
  const lines = [
    `# QA recipe: ${r.id}`,
    ``,
    r.purpose,
    ``,
    `- Platform: \`${r.platform}\` · instance expected for \`${dir}\`${r.expect.instances && r.expect.instances > 1 ? ` (${r.expect.instances} instances)` : ""}`,
    `- Files: ${Object.keys(r.files).map((f) => `\`${f}\``).join(", ")}`,
    r.homeEntry ? `- Isolated \`~/.claude.json\` project entry: \`${JSON.stringify(r.homeEntry)}\`` : null,
    ``,
    `## Expected (isolated home, \`npm run qa -- verify\`)`,
    ``,
    `- Findings: ${must}`,
    `- Threat scenarios: ${scenarios}`,
    `- Must stay absent: ${r.expect.mustNot.join(", ") || "—"}${Object.keys(r.expect.scenarios).length > 0 ? " and every other scenario" : " and any scenario"}`,
    r.expect.notes ? `- Notes containing: ${r.expect.notes.map((n) => `“${n}”`).join(", ")}` : null,
    ``,
    r.sessionWarning ? `> **Warning.** ${r.sessionWarning}\n` : null,
    `## Try it with a real session`,
    ``,
    `> ${LIVE_CAVEAT}`,
    ``,
    ...r.steps.flatMap((s, i) => [
      `${i + 1}. **Do:** ${s.action}`,
      `   **Expect:** ${s.expect}`,
      `   **Look at:** ${s.page}`,
    ]),
    ``,
    `## Reset`,
    ``,
    "`npm run qa -- lab` rewrites this recipe's files (your other files stay); `npm run qa -- lab --reset` wipes projects/ and home/. Live-mode residue in your real `~/.claude.json` (an entry keyed by this path) is yours to remove.",
    ``,
    `---`,
    SR4_LINE,
    ``,
  ];
  return lines.filter((l): l is string => l !== null).join("\n");
}

function renderIndex(lab: LabPaths): string {
  return [
    `# AgentLens QA lab`,
    ``,
    `Generated fixtures for exercising AgentLens against real agent sessions. Everything here is AgentLens-owned test data; AgentLens never writes agent configuration (SR1).`,
    ``,
    `- \`projects/<recipe>/\` — one disposable project per feature, each with a \`QA.md\` card and its own \`.git\` marker.`,
    `- \`home/\` — an isolated HOME for deterministic runs (\`--isolated\`, \`verify\`); no credentials, so a real \`claude\` launched here would need to log in.`,
    `- \`data/\` — lab snapshots and observed events (\`AGENTLENS_DATA_DIR\`), separate from your real \`data/\`.`,
    ``,
    `| Recipe | Purpose |`,
    `|---|---|`,
    ...RECIPES.map((r) => `| [${r.id}](projects/${r.id}/QA.md) | ${r.purpose} |`),
    ``,
    `Commands (from the repo root): \`npm run qa -- up\` (dashboard + watch on this lab) · \`npm run qa -- claude <recipe>\` · \`npm run qa -- verify\` · \`npm run qa -- lab --reset\`.`,
    ``,
    `Lab root: \`${lab.root}\``,
    ``,
    `---`,
    SR4_LINE,
    ``,
  ].join("\n");
}

export async function generateLab(labRoot: string, opts: { reset?: boolean } = {}): Promise<LabManifest> {
  const lab = labPaths(labRoot);
  if (opts.reset) {
    await fs.rm(lab.projects, { recursive: true, force: true });
    await fs.rm(lab.home, { recursive: true, force: true });
  }
  const owned: string[] = [];
  for (const [rel, content] of Object.entries(homeFiles(lab))) {
    await writeOwned(path.join(lab.home, rel), serialize(content), owned);
  }
  for (const r of RECIPES) {
    const dir = recipeDir(lab, r.id);
    await writeGitMarker(dir, owned);
    for (const [rel, content] of Object.entries(r.files)) {
      await writeOwned(path.join(dir, rel), serialize(content), owned);
    }
    await writeOwned(path.join(dir, "QA.md"), renderCard(r, lab), owned);
  }
  await writeOwned(path.join(lab.root, "README.md"), renderIndex(lab), owned);
  await fs.mkdir(path.join(lab.data, "snapshots"), { recursive: true });
  const manifest: LabManifest = { generatedAt: new Date().toISOString(), lab, recipes: RECIPES.map((r) => r.id), owned };
  await fs.writeFile(path.join(lab.root, "lab.json"), JSON.stringify(manifest, null, 2) + "\n");
  return manifest;
}
