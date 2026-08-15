import { promises as fs } from "fs";
import path from "path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { REPO_ROOT, buildMachine, rmMachine, runCollector, type Machine } from "./helpers/machine";

// SR3 — local-only by default: the collector must complete with zero network
// activity. The helpers/net-observe.cjs preload records and blocks every
// network primitive (net/tls/dgram/dns); an empty report file plus a clean
// exit proves the run made no egress attempt.

describe("SR3 — collector makes zero network calls", () => {
  let m: Machine;

  beforeAll(async () => {
    m = await buildMachine();
  });
  afterAll(async () => rmMachine(m));

  it("collector completes under a block-all-network preload with no attempts recorded", async () => {
    const reportFile = path.join(m.root, "net-observe.ndjson");
    const preload = path.join(REPO_ROOT, "tests", "helpers", "net-observe.cjs");
    const run = await runCollector(m, {
      NODE_OPTIONS: `--require ${preload}`,
      NET_OBSERVE_OUT: reportFile,
    });

    expect(run.result.status, run.result.stderr).toBe(0);
    expect(run.snapshotPath).not.toBeNull();

    let attempts = "";
    try {
      attempts = await fs.readFile(reportFile, "utf8");
    } catch {
      // file never created — zero attempts
    }
    expect(attempts).toBe("");
  });
});
