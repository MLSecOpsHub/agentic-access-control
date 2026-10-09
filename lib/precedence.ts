import type { Effect, PermissionRule } from "./schema";

export interface ReachabilityResult {
  effect: Effect;
  rule: PermissionRule;
}

/**
 * Whether `tool` is reachable via an UNBOUNDED rule (bare tool name, `Tool(*)`,
 * `Tool(*:*)`, or the global `*` wildcard) — the same "unbounded surface"
 * concept lib/heuristics.ts H2 already checks inline, generalized to any tool
 * and made precedence-aware (deny/ask/allow, effect-first, per precedenceRank).
 * Scoped matchers (e.g. `Bash(npm test)`) are deliberately excluded: they say
 * nothing about whether the tool is reachable *in general*, and a full
 * command-argument matcher engine is out of scope (docs/threat-scenarios.md
 * §4 "Reachability, not existence").
 */
export function resolveToolReachability(
  rules: PermissionRule[],
  tool: string,
): ReachabilityResult | null {
  const isUnbounded = (matcher: string) =>
    matcher === tool ||
    new RegExp(`^${tool}\\(\\s*\\*\\s*\\)$`).test(matcher) ||
    new RegExp(`^${tool}\\(\\s*\\*:\\*\\s*\\)$`).test(matcher);

  const candidates = rules.filter(
    (r) => r.matcher === "*" || (r.tool === tool && isUnbounded(r.matcher)),
  );
  if (candidates.length === 0) return null;

  const sorted = [...candidates].sort((a, b) => a.precedenceRank - b.precedenceRank);
  const winner = sorted[0];
  return { effect: winner.effect, rule: winner };
}
