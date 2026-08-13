import type { AgentInstance, McpServer, RiskFinding, Severity } from "./schema";

// Risk heuristics H1–H7 (docs/collectors.md §6). Pure functions over the
// normalized data — they never touch disk, so they are testable on fixtures.

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

    // H5 — deny rule co-existing with a broader allow on the same tool.
    const allowsByTool = new Map<string, string[]>();
    for (const r of inst.permissionRules) {
      if (r.effect !== "allow" || !r.tool) continue;
      const broad =
        r.matcher === "*" || r.matcher === r.tool || /^[A-Za-z]+\(\s*\*(:\*)?\s*\)$/.test(r.matcher);
      if (broad) allowsByTool.set(r.tool, [...(allowsByTool.get(r.tool) ?? []), r.matcher]);
    }
    for (const r of inst.permissionRules) {
      if (r.effect === "deny" && r.tool && allowsByTool.has(r.tool)) {
        add("H5", "medium", `Deny "${r.matcher}" shadowed by broader allow on ${r.tool}`,
          `deny ${r.matcher} vs allow ${allowsByTool.get(r.tool)!.join(", ")}`, inst.id, r.sourceFile);
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
