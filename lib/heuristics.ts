import type { AgentInstance, McpServer, RiskFinding, Severity } from "./schema";

// Risk heuristics (docs/collectors.md §6). Pure functions over the normalized
// data — they never touch disk, so they are testable on fixtures.
// H5 ("deny shadowed by broader allow") is RETIRED: first-party docs specify
// global deny → ask → allow evaluation across all settings files, so a deny is
// never shadowed by an allow. See local/mvp-review-accuracy-analysis.md (F1).

const RISKY_BARE_TOOLS = new Set(["Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"]);
const SECRET_KEY = /(TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL)/i;
const BYPASS_MODE = /(bypass|yolo|danger|full-access)/i;
const PIPE_TO_SHELL = /(curl|wget)[^|;]*\|\s*(ba|z)?sh\b/;
// A package token carrying an explicit version: name@1.2.3, @scope/name@^1.2,
// or pip-style name==1.2. False negatives fall through to the unpinned (high)
// variant — over-warning is the acceptable direction here.
const PINNED_PACKAGE = /\S@[~^=]?\d|\S==\d/;

interface Ctx {
  instances: AgentInstance[];
  mcpServers: McpServer[];
}

export function runHeuristics(ctx: Ctx): RiskFinding[] {
  const findings: RiskFinding[] = [];
  let n = 0;
  const add = (
    heuristicId: RiskFinding["heuristicId"],
    severity: Severity,
    title: string,
    evidence: string,
    instanceId: string | null,
    sourceFile: string | null,
  ) => {
    findings.push({
      id: `${heuristicId}:${instanceId ?? "global"}:${n++}`,
      heuristicId,
      severity,
      title,
      evidence,
      instanceId,
      sourceFile,
    });
  };

  for (const inst of ctx.instances) {
    // H1 — bypass modes: all gating off. Attributed to the file that actually
    // contributed the winning mode (Step 5), not configFiles[0].
    if (inst.defaultMode && BYPASS_MODE.test(inst.defaultMode)) {
      add("H1", "critical", `Permission gating bypassed (mode "${inst.defaultMode}")`,
        `defaultMode: ${inst.defaultMode}`, inst.id, inst.defaultModeSourceFile);
    }

    for (const rule of inst.permissionRules) {
      // H2 — wildcard allow on unbounded tool surface.
      if (rule.effect === "allow") {
        const bare = RISKY_BARE_TOOLS.has(rule.matcher);
        const wild =
          rule.matcher === "*" ||
          /^[A-Za-z]+\(\s*\*\s*\)$/.test(rule.matcher) ||
          /^[A-Za-z]+\(\s*\*:\*\s*\)$/.test(rule.matcher);
        if (bare || wild) {
          add("H2", "high", `Wildcard allow rule "${rule.matcher}"`,
            `${rule.effect} ${rule.matcher} (${rule.sourceLevel})`, inst.id, rule.sourceFile);
        }
      }
    }

    // H6 — sandbox off or escapable where the platform offers one. Attributed
    // via per-field provenance from the collector's tier merge (Step 5).
    if (inst.sandbox) {
      if (inst.sandbox.enabled === false) {
        add("H6", "medium", "Sandbox disabled", "sandbox.enabled: false", inst.id,
          inst.sandbox.fieldSources.enabled ?? null);
      } else if (inst.sandbox.allowUnsandboxedCommands === true) {
        add("H6", "medium", "Unsandboxed commands allowed",
          "sandbox.allowUnsandboxedCommands: true", inst.id,
          inst.sandbox.fieldSources.allowUnsandboxedCommands ?? null);
      }
    }

    // H7 — hook pipes remote content to a shell.
    for (const hook of inst.hooks) {
      if (PIPE_TO_SHELL.test(hook.commandPreview)) {
        add("H7", "low", `${hook.event} hook pipes remote content to a shell`,
          hook.commandPreview, inst.id, hook.sourceFile);
      }
    }
  }

  for (const srv of ctx.mcpServers) {
    // H3 — remote package runner. Unpinned executes latest upstream on every
    // start (high). A pinned version still fetches from the registry at
    // startup, so it stays a lower-severity variant (Step 5 fix: pinned specs
    // were previously flagged with the unpinned claim text — false).
    if (srv.transport === "stdio") {
      const cmd = [srv.commandOrUrl, ...srv.args].join(" ");
      if (/\bnpx\b[^\n]*\s-y\b/.test(cmd) || /\b(uvx|pipx run)\b/.test(cmd)) {
        if (PINNED_PACKAGE.test(cmd)) {
          add("H3", "medium", `MCP server "${srv.name}" launched via remote package runner (version pinned)`,
            `${cmd} — fetched from the package registry at startup; version pinned`,
            srv.instanceId, srv.sourceFile);
        } else {
          add("H3", "high", `MCP server "${srv.name}" launched via unpinned package runner`,
            `${cmd} — executes latest upstream on every start`, srv.instanceId, srv.sourceFile);
        }
      }
    }
    // H4 — secret-suggestive env key names (values already dropped by SR2).
    const secretKeys = srv.envKeys.filter((k) => SECRET_KEY.test(k));
    if (secretKeys.length > 0) {
      add("H4", "high", `MCP server "${srv.name}" configured with credential env: ${secretKeys.join(", ")}`,
        `env keys: ${secretKeys.join(", ")} (values redacted)`, srv.instanceId, srv.sourceFile);
    }
  }

  return findings;
}
