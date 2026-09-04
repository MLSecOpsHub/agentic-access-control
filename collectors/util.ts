import { promises as fs } from "fs";
import path from "path";
import { createHash } from "crypto";

// Shared collector plumbing. SR1: everything here is read-only — the only
// write API in the collector tree lives in collect.ts and targets
// data/snapshots/ exclusively.

const MAX_CONFIG_BYTES = 5 * 1024 * 1024; // T9: parser-bomb cap

// SR2: parse issues carry FIXED CODES only — never exception message text.
// Node's JSON.parse errors echo fragments of the offending input, and V8's
// truncation defeats pattern-based redaction (review finding F3, probe P1).
export type ParseIssueCode = "ERR_SYMLINK" | "ERR_SIZE_CAP" | "ERR_JSON_SYNTAX" | "ERR_NOT_OBJECT";

export const PARSE_ISSUE_TEXT: Record<ParseIssueCode, string> = {
  ERR_SYMLINK: "symlinked config skipped (T4 path-traversal guard)",
  ERR_SIZE_CAP: `config exceeds ${MAX_CONFIG_BYTES} byte cap, skipped (T9)`,
  ERR_JSON_SYNTAX: "config is not parseable JSON",
  ERR_NOT_OBJECT: "top-level JSON is not an object",
};

export interface ParseIssue {
  file: string;
  code: ParseIssueCode;
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
    issues.push({ file, code: "ERR_SYMLINK" });
    return undefined;
  }
  if (!stat.isFile()) return undefined;
  if (stat.size > MAX_CONFIG_BYTES) {
    issues.push({ file, code: "ERR_SIZE_CAP" });
    return undefined;
  }
  try {
    const raw = await fs.readFile(file, "utf8");
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      issues.push({ file, code: "ERR_NOT_OBJECT" });
      return undefined;
    }
    return parsed as Record<string, unknown>;
  } catch {
    issues.push({ file, code: "ERR_JSON_SYNTAX" }); // exception text intentionally discarded
    return undefined;
  }
}

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "target", ".venv"]);

/**
 * Walk `root` up to `maxDepth`, returning files whose basename is in `names`.
 * Symlinks are never followed (T4); noisy build dirs are skipped. A resolved-
 * path prefix check keeps every visited entry under the scanned root — belt
 * and braces on top of the symlink skip.
 */
export async function findFilesNamed(root: string, names: Set<string>, maxDepth = 4): Promise<string[]> {
  const out: string[] = [];
  const rootResolved = path.resolve(root);
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
      const resolved = path.resolve(full);
      if (resolved !== rootResolved && !resolved.startsWith(rootResolved + path.sep)) continue;
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
