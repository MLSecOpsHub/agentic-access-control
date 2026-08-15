import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { redact } from "@/lib/redact";
import { SnapshotSchema } from "@/lib/schema";
import {
  SECRETS,
  buildMachine,
  rmMachine,
  runCollector,
  type CollectorRun,
  type Machine,
} from "./helpers/machine";

// SR2 — secrets redaction at collection time (security-architecture.md §3).
// Two layers: a unit corpus over redact() covering every pattern class, and an
// end-to-end run of the real collector over secret-seeded configs — including
// a malformed JSON file (probe P1: parser errors must not echo config bytes).

describe("SR2 — redact() unit corpus", () => {
  const cases: Array<[string, string]> = [
    ["openai/anthropic-style key", `run with ${SECRETS.openai} inline`],
    ["github token", `token ${SECRETS.github} end`],
    ["github fine-grained pat", `${SECRETS.githubPat}`],
    ["aws access key id", `aws key ${SECRETS.aws} here`],
    ["slack token", `slack ${SECRETS.slack}`],
    ["bearer header", `-H 'Authorization: Bearer ${SECRETS.bearerToken}'`],
    ["jwt", `--jwt ${SECRETS.jwt}`],
    ["long base64 run", `blob ${SECRETS.b64}`],
    ["long hex run", `sig ${SECRETS.hex}`],
    ["key=value capture", `password=${SECRETS.keyedValue}`],
  ];

  it.each(cases)("redacts %s", (_label, input) => {
    const out = redact(input);
    for (const secret of [
      SECRETS.openai,
      SECRETS.github,
      SECRETS.githubPat,
      SECRETS.aws,
      SECRETS.slack,
      SECRETS.bearerToken,
      SECRETS.jwt,
      SECRETS.b64,
      SECRETS.hex,
      SECRETS.keyedValue,
    ]) {
      expect(out).not.toContain(secret);
    }
    expect(out).toContain("[REDACTED]");
  });

  it("key=value redaction keeps the key name", () => {
    expect(redact(`password=${SECRETS.keyedValue}`)).toContain("password=");
  });
});

describe("SR2 — end-to-end: secret-seeded machine produces a clean snapshot", () => {
  let m: Machine;
  let run: CollectorRun;

  beforeAll(async () => {
    m = await buildMachine();
    run = await runCollector(m);
    expect(run.result.status, run.result.stderr).toBe(0);
  });
  afterAll(async () => rmMachine(m));

  it("no seeded secret survives into the snapshot file", () => {
    const text = run.snapshotText!;
    for (const [name, secret] of Object.entries(SECRETS)) {
      expect(text.includes(secret), `secret "${name}" leaked into snapshot`).toBe(false);
    }
  });

  it("snapshot passes the CI token-pattern grep (sk-, AKIA, ghp_, Bearer, xox)", () => {
    const text = run.snapshotText!;
    expect(text).not.toMatch(/\bsk-[A-Za-z0-9_-]{8,}/);
    expect(text).not.toMatch(/\bAKIA[0-9A-Z]{16}/);
    expect(text).not.toMatch(/\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}/);
    expect(text).not.toMatch(/Bearer\s+[A-Za-z0-9._~+/=-]{16,}/i);
    expect(text).not.toMatch(/\bxox[baprs]-[A-Za-z0-9-]{10,}/);
  });

  it("MCP env values are dropped; key names are kept", () => {
    const snapshot = SnapshotSchema.parse(JSON.parse(run.snapshotText!));
    const keys = snapshot.mcpServers.flatMap((s) => s.envKeys);
    expect(keys).toContain("GITHUB_TOKEN");
    expect(keys).toContain("PGPASSWORD");
  });

  it("scalar fields (defaultMode) are redacted", () => {
    const snapshot = SnapshotSchema.parse(JSON.parse(run.snapshotText!));
    const project = snapshot.instances.find(
      (i) => i.platform === "claude-code" && i.projectPath === m.project,
    );
    expect(project?.defaultMode).toBe("[REDACTED]");
  });

  it("malformed JSON yields a fixed error code, never parser message text (probe P1)", () => {
    const snapshot = SnapshotSchema.parse(JSON.parse(run.snapshotText!));
    const parseFindings = snapshot.findings.filter((f) => f.heuristicId === "PARSE");
    const bad = parseFindings.find((f) => f.sourceFile?.startsWith(m.projectBad));
    expect(bad).toBeDefined();
    expect(bad!.evidence).toMatch(/^ERR_JSON_SYNTAX:/);
    expect(bad!.evidence).not.toContain("sk-");
    expect(bad!.evidence).not.toContain(SECRETS.openai);
  });
});
