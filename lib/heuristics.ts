import type { AgentInstance, McpServer, RiskFinding, Severity } from "./schema";

// Risk heuristics (docs/collectors.md §6). Pure functions over the normalized
// data — they never touch disk, so they are testable on fixtures.
// H5 ("deny shadowed by broader allow") is RETIRED: first-party docs specify
// global deny → ask → allow evaluation across all settings files, so a deny is
// never shadowed by an allow. See local/mvp-review-accuracy-analysis.md (F1).

// Claude Code names, then Gemini CLI names (vendor docs: `tools.allowed` with a
// bare tool name bypasses confirmation for every invocation of that tool).
const RISKY_BARE_TOOLS = new Set([
  "Bash", "Write", "Edit", "MultiEdit", "NotebookEdit",
  "run_shell_command", "write_file", "replace", "ShellTool",
]);
const SECRET_KEY = /(TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL)/i;
const BYPASS_MODE = /(bypass|yolo|danger|full-access)/i;
// Modes that approve actions without asking, short of bypass, with the
// vendor's own wording (docs verified 2026-10-11). Platform vocabulary differs.
const REDUCED_OVERSIGHT_MODES: Record<string, Record<string, string>> = {
  "claude-code": {
    auto: "auto: a background classifier reviews actions instead of you — the vendor's built-in starting mode for interactive sessions since Claude Code v2.1.283",
    acceptEdits: "acceptEdits: file edits and common filesystem commands in the working directories run without prompts",
  },
  "gemini-cli": {
    auto_edit: "auto_edit: edit tools are auto-approved (vendor docs)",
  },
  "codex-cli": {
    never: "approval_policy never: no approval prompts — the sandbox is the only remaining gate",
  },
};
const underProject = (file: string | null, projectPath: string | null) =>
  projectPath !== null && file !== null && file.startsWith(projectPath + "/");
export const PIPE_TO_SHELL = /(curl|wget)[^|;]*\|\s*(ba|z)?sh\b/;
// A package token carrying an explicit version: name@1.2.3, @scope/name@^1.2,
// or pip-style name==1.2. False negatives fall through to the unpinned (high)
// variant — over-warning is the acceptable direction here.
export const PINNED_PACKAGE = /\S@[~^=]?\d|\S==\d/;

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

    // H8 — reduced-oversight mode (low): reported once, on the instance whose
    // own tier set it (a project instance inheriting the user tier's mode
    // would only repeat the user instance's finding). Claude Code ignores
    // "auto" set in project files (vendor), so that declaration is inert.
    const reduced = inst.defaultMode ? REDUCED_OVERSIGHT_MODES[inst.platform]?.[inst.defaultMode] : undefined;
    if (reduced && inst.defaultMode && !BYPASS_MODE.test(inst.defaultMode)) {
      const ownTier = inst.projectPath === null || underProject(inst.defaultModeSourceFile, inst.projectPath);
      const inert =
        inst.platform === "claude-code" && inst.defaultMode === "auto" && underProject(inst.defaultModeSourceFile, inst.projectPath);
      if (ownTier && !inert) {
        add("H8", "low", `Reduced-oversight mode configured ("${inst.defaultMode}")`,
          `defaultMode: ${inst.defaultMode} — ${reduced}`, inst.id, inst.defaultModeSourceFile);
      }
    }

    // H9 — the confirmation shown before entering bypassPermissions is skipped.
    for (const c of inst.controls) {
      if (c.key === "skipDangerousModePermissionPrompt" && c.value === "true") {
        const ownTier = inst.projectPath === null || underProject(c.sourceFile, inst.projectPath);
        if (ownTier) {
          add("H9", "low", "Bypass-mode confirmation dialog suppressed",
            "skipDangerousModePermissionPrompt: true — vendor: skips the confirmation dialog before bypassPermissions mode",
            inst.id, c.sourceFile);
        }
      }
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
      } else if (inst.sandbox.excludedCommands.length > 0) {
        add("H6", "low", `Sandbox excludes ${inst.sandbox.excludedCommands.length} command pattern(s)`,
          `sandbox.excludedCommands: ${inst.sandbox.excludedCommands.join(", ")} — run outside the sandbox (no filesystem limits, no network proxy)`,
          inst.id, inst.sandbox.fieldSources.excludedCommands ?? null);
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
