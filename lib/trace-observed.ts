import type { ObservedUsage } from "./scenario-catalog";
import { loadTraceEvents } from "./trace-store";

// Build the observed-usage view the scenario engine consumes (dashboard only):
// MCP server names called in traced sessions within the window, with the
// sessions and cwds they were called from. Best-effort: an empty map when no
// traces exist.

export async function loadObservedUsage(windowDays = 7): Promise<ObservedUsage> {
  const usage: ObservedUsage = { mcpServersUsed: new Map(), windowDays };
  try {
    const { events } = await loadTraceEvents();
    const since = Date.now() - windowDays * 24 * 60 * 60 * 1000;
    for (const e of events) {
      if (e.kind !== "mcp-call" || !e.sessionId || Date.parse(e.eventAt) < since) continue;
      const server = typeof e.detail.server === "string" ? e.detail.server : null;
      if (!server) continue;
      const u = usage.mcpServersUsed.get(server) ?? { sessions: new Set<string>(), cwds: new Set<string>(), lastAt: e.eventAt };
      u.sessions.add(e.sessionId);
      if (e.cwd) u.cwds.add(e.cwd);
      if (e.eventAt > u.lastAt) u.lastAt = e.eventAt;
      usage.mcpServersUsed.set(server, u);
    }
  } catch {
    // no trace store yet
  }
  return usage;
}
