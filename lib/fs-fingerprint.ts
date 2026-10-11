import { promises as fs } from "fs";
import path from "path";
import { SKIP_DIRS } from "../collectors/util";

// Bounded, read-only size+mtime fingerprint of a directory tree, used for the
// session window diff (docs/session-trace.md §8). Same walk rules as the
// collectors: symlinks are never followed, noisy build dirs are skipped, and a
// resolved-path prefix check keeps every entry under the root (T4). v1 does
// not hash content: "touched" means the mtime moved while the size held.

export interface FileStamp {
  size: number;
  mtimeMs: number;
}

export interface Fingerprint {
  root: string;
  takenAt: string;
  files: Record<string, FileStamp>; // path relative to root
  count: number;
  bytes: number;
  truncated: "files" | "bytes" | "time" | null;
}

export interface FingerprintCaps {
  maxFiles: number;
  maxBytes: number;
  maxMs: number;
  maxDepth: number;
}

export const DEFAULT_CAPS: FingerprintCaps = { maxFiles: 20_000, maxBytes: 200 * 1024 * 1024, maxMs: 10_000, maxDepth: 12 };

export async function fingerprintTree(root: string, caps: FingerprintCaps = DEFAULT_CAPS): Promise<Fingerprint> {
  const rootResolved = path.resolve(root);
  const fp: Fingerprint = { root: rootResolved, takenAt: new Date().toISOString(), files: {}, count: 0, bytes: 0, truncated: null };
  const started = Date.now();
  const stack: Array<{ dir: string; depth: number }> = [{ dir: rootResolved, depth: 0 }];
  while (stack.length > 0 && fp.truncated === null) {
    const { dir, depth } = stack.pop()!;
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (Date.now() - started > caps.maxMs) {
        fp.truncated = "time";
        break;
      }
      if (e.isSymbolicLink()) continue;
      const full = path.join(dir, e.name);
      const resolved = path.resolve(full);
      if (resolved !== rootResolved && !resolved.startsWith(rootResolved + path.sep)) continue;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && depth < caps.maxDepth) stack.push({ dir: full, depth: depth + 1 });
      } else if (e.isFile()) {
        let st;
        try {
          st = await fs.lstat(full);
        } catch {
          continue;
        }
        fp.count++;
        fp.bytes += st.size;
        if (fp.count > caps.maxFiles) {
          fp.truncated = "files";
          break;
        }
        if (fp.bytes > caps.maxBytes) {
          fp.truncated = "bytes";
          break;
        }
        fp.files[path.relative(rootResolved, full)] = { size: st.size, mtimeMs: st.mtimeMs };
      }
    }
  }
  return fp;
}

export type FsChange = "added" | "modified" | "touched" | "removed";

export function diffFingerprints(before: Fingerprint, after: Fingerprint): Array<{ path: string; change: FsChange }> {
  const out: Array<{ path: string; change: FsChange }> = [];
  for (const [p, a] of Object.entries(after.files)) {
    const b = before.files[p];
    if (!b) out.push({ path: p, change: "added" });
    else if (b.size !== a.size) out.push({ path: p, change: "modified" });
    else if (b.mtimeMs !== a.mtimeMs) out.push({ path: p, change: "touched" });
  }
  for (const p of Object.keys(before.files)) if (!(p in after.files)) out.push({ path: p, change: "removed" });
  return out.sort((x, y) => x.path.localeCompare(y.path));
}
