import { promises as fs } from "fs";
import path from "path";
import { spawn, type ChildProcess } from "child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { REPO_ROOT } from "./helpers/machine";

// SR3 — no-egress page crawl: boot the real dashboard server, crawl every
// internal page reachable from the overview, and assert that no loadable
// resource (src/href/srcset/action, CSS url()) points off-machine. Everything
// must ship in the repo — no CDN assets, fonts, analytics, or update checks.

const PORT = 3777;
const ORIGIN = `http://127.0.0.1:${PORT}`;

let server: ChildProcess | null = null;

async function waitForServer(timeoutMs = 90_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown = null;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${ORIGIN}/`, { redirect: "manual" });
      if (res.status < 500) return;
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`dashboard server did not come up on ${ORIGIN}: ${lastErr}`);
}

describe("SR3 — rendered pages load no external resources", () => {
  beforeAll(async () => {
    const nextBin = path.join(REPO_ROOT, "node_modules", "next", "dist", "bin", "next");
    server = spawn(
      process.execPath,
      [nextBin, "dev", "-H", "127.0.0.1", "-p", String(PORT)],
      {
        cwd: REPO_ROOT,
        env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" },
        stdio: "ignore",
        detached: true,
      },
    );
    await waitForServer();
  });

  afterAll(() => {
    if (server?.pid) {
      try {
        process.kill(-server.pid, "SIGTERM"); // negative pid: kill the dev-server process group
      } catch {
        server.kill("SIGKILL");
      }
    }
  });

  it("crawl finds only same-origin/relative resource URLs", async () => {
    const seen = new Set<string>();
    const queue = ["/", "/mcp", "/findings", "/live"];
    const external: string[] = [];

    while (queue.length > 0 && seen.size < 15) {
      const route = queue.shift()!;
      if (seen.has(route)) continue;
      seen.add(route);

      const res = await fetch(`${ORIGIN}${route}`);
      expect(res.status, `GET ${route}`).toBeLessThan(500);
      const html = await res.text();

      for (const match of html.matchAll(/(?:src|href|srcset|action)\s*=\s*"([^"]*)"/g)) {
        const url = match[1];
        if (/^(https?:)?\/\//i.test(url) && !url.startsWith(ORIGIN)) {
          external.push(`${route} → ${url}`);
        }
        // follow internal page links to cover instance detail pages
        if (url.startsWith("/") && !url.startsWith("//") && !url.startsWith("/_next")) {
          const clean = url.split("#")[0].split("?")[0];
          if (!seen.has(clean)) queue.push(clean);
        }
      }
      for (const match of html.matchAll(/url\(\s*['"]?(https?:\/\/[^)'"]+)/gi)) {
        external.push(`${route} → css ${match[1]}`);
      }
    }

    expect(seen.size).toBeGreaterThanOrEqual(4);
    expect(external).toEqual([]);
  });

  it("stylesheet ships no remote imports or url() fetches", async () => {
    const css = await fs.readFile(path.join(REPO_ROOT, "app", "globals.css"), "utf8");
    expect(css).not.toMatch(/@import\s+url?\(?\s*['"]?https?:/i);
    expect(css).not.toMatch(/url\(\s*['"]?https?:/i);
    expect(css).not.toMatch(/@font-face[^}]*url\(/i);
  });
});
