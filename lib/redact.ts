// SR2 — secrets redaction at collection time.
// Every collected string passes through redact() before entering a snapshot
// object. The pattern list lives in redact-patterns.mjs so the hook script
// (plain node, no build) and this TypeScript code cannot drift apart.

import { redact, truncate } from "./redact-patterns.mjs";

export { redact, truncate };

export function redactAll(values: string[]): string[] {
  return values.map(redact);
}
