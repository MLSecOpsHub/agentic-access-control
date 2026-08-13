import os from "os";

export function timeAgo(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return "unknown age";
  if (ms < 0) return "just now"; // clock skew tolerance
  const min = Math.floor(ms / 60_000);
  if (min < 1) return "just now";
  if (min < 60) return `${min} min ago`;
  const h = Math.floor(min / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.floor(h / 24)} days ago`;
}

export function isStale(iso: string, hours = 24): boolean {
  return Date.now() - new Date(iso).getTime() > hours * 3_600_000;
}

export function shortHash(hash: string): string {
  return hash.slice(0, 12);
}

export function shortPath(p: string): string {
  const home = os.homedir();
  return p.startsWith(home) ? `~${p.slice(home.length)}` : p;
}
