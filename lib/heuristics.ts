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
    // H1 — bypass modes: all gating off.
    if (inst.defaultMode && BYPASS_MODE.test(inst.defaultMode)) {
      add("H1", "critical", `Permission gating bypassed (mode "${inst.defaultMode}")`,
        `defaultMode: ${inst.defaultMode}`, inst.id, inst.configFiles[0] ?? null);
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

    // H6 — sandbox off or escapable where the platform offers one.
    if (inst.sandbox) {
      if (inst.sandbox.enabled === false) {
        add("H6", "medium", "Sandbox disabled", "sandbox.enabled: false", inst.id, inst.configFiles[0] ?? null);
      } else if (inst.sandbox.allowUnsandboxedCommands === true) {
        add("H6", "medium", "Unsandboxed commands allowed",
          "sandbox.allowUnsandboxedCommands: true", inst.id, inst.configFiles[0] ?? null);
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
    // H3 — unpinned launcher: executes latest upstream on every start.
    if (srv.transport === "stdio") {
      const cmd = [srv.commandOrUrl, ...srv.args].join(" ");
      if (/\bnpx\b[^\n]*\s-y\b/.test(cmd) || /\b(uvx|pipx run)\b/.test(cmd)) {
        add("H3", "high", `MCP server "${srv.name}" launched via unpinned package runner`,
          cmd, srv.instanceId, srv.sourceFile);
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
