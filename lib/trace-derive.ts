import type { TraceEvent } from "./trace";
import { traceEventId } from "./trace";
import { PINNED_PACKAGE } from "./heuristics";
import { stripUrl } from "./trace-project.mjs";

// Derived trace events: hosts and package installs parsed out of a shell
// command string. Confidence "derived" — the command was declared; whether it
// ran as parsed is not observed (docs/session-trace.md §7).

export const URL_RE = /https?:\/\/[^\s'"`<>|;)]+/g;
export const MANAGER_RE = /^(?:sudo\s+)?(npm|pnpm|yarn|bun|pip3?|uv|uvx|npx|cargo|go|gem|brew|apt-get|apt)\s+(.*)$/;

export function specsFrom(manager: string, rest: string): string[] {
  const words = rest.trim().split(/\s+/);
  const positional = (from: number) => words.slice(from).filter((w) => w && !w.startsWith("-"));
  const verb = words[0] ?? "";
  switch (manager) {
    case "npm": case "pnpm": case "yarn": case "bun":
      return ["install", "add", "i"].includes(verb) ? positional(1) : [];
    case "pip": case "pip3":
      return verb === "install" ? positional(1) : [];
    case "uv":
      if (verb === "add") return positional(1);
      if (verb === "pip" && words[1] === "install") return positional(2);
      return [];
    case "uvx":
      return positional(0).slice(0, 1);
    case "npx":
      return words.includes("-y") || words.includes("--yes") ? positional(0).slice(0, 1) : [];
    case "cargo":
      return verb === "add" ? positional(1) : [];
    case "go":
      return verb === "get" || verb === "install" ? positional(1) : [];
    case "gem": case "brew": case "apt": case "apt-get":
      return verb === "install" ? positional(1) : [];
    default:
      return [];
  }
}

export function deriveFromShell(ev: TraceEvent): TraceEvent[] {
  const out: TraceEvent[] = [];
  const mk = (kind: TraceEvent["kind"], resource: string, detail: TraceEvent["detail"]): TraceEvent => {
    const base = { ...ev, kind, resource, detail, confidence: "derived" as const };
    return { ...base, eventId: traceEventId(base) };
  };
  const seen = new Set<string>();
  for (const m of ev.resource.matchAll(URL_RE)) {
    const u = stripUrl(m[0]);
    if (u && !seen.has(u)) {
      seen.add(u);
      out.push(mk("web", u, { via: "shell" }));
    }
  }
  for (const segment of ev.resource.split(/&&|\|\||;|\|/)) {
    const m = MANAGER_RE.exec(segment.trim());
    if (!m) continue;
    const manager = m[1] === "pip3" ? "pip" : m[1] === "apt-get" ? "apt" : m[1];
    for (const spec of specsFrom(m[1], m[2])) {
      const key = `${manager}:${spec}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(mk("dependency", key, { manager, spec, pinned: PINNED_PACKAGE.test(spec) }));
    }
  }
  return out;
}
