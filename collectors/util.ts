import { promises as fs } from "fs";
import path from "path";
import { createHash } from "crypto";

// Shared collector plumbing. SR1: everything here is read-only — the only
// write API in the collector tree lives in collect.ts and targets
// data/snapshots/ exclusively.

const MAX_CONFIG_BYTES = 5 * 1024 * 1024; // T9: parser-bomb cap

export interface ParseIssue {
  file: string;
  message: string;
}

/** Read + JSON-parse a config file. Missing file → undefined; malformed → issue. */
export async function readJsonConfig(
  file: string,
  issues: ParseIssue[],
): Promise<Record<string, unknown> | undefined> {
  let stat;
  try {
    stat = await fs.lstat(file); // lstat: never follow a symlinked config (T4)
  } catch {
    return undefined;
  }
  if (stat.isSymbolicLink()) {
    issues.push({ file, message: "symlinked config skipped (T4 path-traversal guard)" });
    return undefined;
  }
  if (!stat.isFile()) return undefined;
  if (stat.size > MAX_CONFIG_BYTES) {
    issues.push({ file, message: `config exceeds ${MAX_CONFIG_BYTES} byte cap, skipped (T9)` });
    return undefined;
  }
  try {
    const raw = await fs.readFile(file, "utf8");
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      issues.push({ file, message: "top-level JSON is not an object" });
      return undefined;
    }
    return parsed as Record<string, unknown>;
  } catch (err) {
    issues.push({ file, message: `unparseable JSON: ${(err as Error).message}` });
    return undefined;
  }
}

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "target", ".venv"]);

/**
 * Walk `root` up to `maxDepth`, returning files whose basename is in `names`.
 * Symlinks are never followed (T4); noisy build dirs are skipped.
 */
export async function findFilesNamed(root: string, names: Set<string>, maxDepth = 4): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > maxDepth) return;
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) await walk(full, depth + 1);
      } else if (e.isFile() && names.has(e.name)) {
        out.push(full);
      }
    }
  }
  await walk(root, 0);
  return out;
}

export function hash8(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 8);
}

export function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}
