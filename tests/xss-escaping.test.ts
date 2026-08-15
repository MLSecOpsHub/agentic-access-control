import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { createElement, type ReactNode } from "react";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { makeRule, makeServer, makeSnapshot, writeSnapshotDir } from "./helpers/snapshots";

// B1/B3 — adversarial config strings must render escaped. Renders the real
// overview page (drift included) against a snapshot seeded with XSS-shaped
// strings and asserts none survive as live markup. React default escaping is
// the mitigation; eslint's react/no-danger ban keeps it that way.

vi.mock("next/link", () => ({
  default: ({ href, children }: { href?: unknown; children?: ReactNode }) =>
    createElement("a", { href: typeof href === "string" ? href : "#" }, children),
}));

const XSS = {
  matcher: `Bash(<img src=x onerror=alert('matcher')>)`,
  title: `<script>alert("finding")</script>`,
  serverName: `github"><svg onload=alert(1)>`,
  command: `npx</td><script>alert("cmd")</script>`,
  projectPath: `/tmp/<iframe src="javascript:alert(2)">`,
};

let base: string;
let originalCwd: string;
let html: string;

beforeAll(async () => {
  base = await fs.mkdtemp(path.join(os.tmpdir(), "agentlens-xss-"));

  const inst = makeSnapshot().instances[0];
  // Same (XSS-shaped) server name in both snapshots, different command → the
  // drift "changed" branch renders before/after commandOrUrl for these strings.
  const previous = makeSnapshot({
    generatedAt: "2026-08-13T00:00:00.000Z",
    mcpServers: [makeServer({ name: XSS.serverName })],
  });
  const current = makeSnapshot({
    instances: [
      {
        ...inst,
        projectPath: XSS.projectPath,
        permissionRules: [makeRule(), makeRule({ effect: "allow", matcher: XSS.matcher, tool: null })],
      },
    ],
    mcpServers: [makeServer({ name: XSS.serverName, commandOrUrl: XSS.command })],
    findings: [
      {
        id: "H1:test",
        heuristicId: "H1",
        severity: "critical",
        title: XSS.title,
        evidence: XSS.matcher,
        instanceId: inst.id,
        sourceFile: null,
      },
    ],
  });
  await writeSnapshotDir(base, [
    { name: "2026-08-13T00-00-00-000Z.json", content: previous },
    { name: "2026-08-14T00-00-00-000Z.json", content: current },
  ]);

  originalCwd = process.cwd();
  process.chdir(base); // Overview reads snapshots from cwd
  const [{ default: Overview }, { renderToStaticMarkup }] = await Promise.all([
    import("@/app/page"),
    import("react-dom/server"),
  ]);
  html = renderToStaticMarkup(await Overview());
});

afterAll(async () => {
  process.chdir(originalCwd);
  await fs.rm(base, { recursive: true, force: true });
});

describe("XSS-shaped config strings render escaped", () => {
  it("page rendered with the adversarial snapshot (drift section included)", () => {
    expect(html.length).toBeGreaterThan(0);
    expect(html).toContain("Drift since previous snapshot");
  });

  it("no injected tag survives as live markup", () => {
    expect(html).not.toContain("<script");
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<svg");
    expect(html).not.toContain("<iframe");
    expect(html).not.toMatch(/<[a-z]+[^>]*\son(error|load)=/i);
  });

  it("the adversarial strings are present — escaped, not dropped", () => {
    expect(html).toContain("&lt;img src=x onerror=alert(&#x27;matcher&#x27;)&gt;");
    expect(html).toContain("&lt;script&gt;");
  });
});

describe("dangerouslySetInnerHTML stays banned in source", () => {
  it("no occurrence in app/ or lib/", async () => {
    const repoRoot = originalCwd;
    const hits: string[] = [];
    async function scan(dir: string): Promise<void> {
      for (const e of await fs.readdir(dir, { withFileTypes: true })) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) await scan(full);
        else if (/\.(ts|tsx)$/.test(e.name)) {
          if ((await fs.readFile(full, "utf8")).includes("dangerouslySetInnerHTML")) hits.push(full);
        }
      }
    }
    await scan(path.join(repoRoot, "app"));
    await scan(path.join(repoRoot, "lib"));
    expect(hits).toEqual([]);
  });
});
