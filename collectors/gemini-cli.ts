import type { CollectorResult } from "./claude-code";

// Gemini CLI collector — STUB. Spec: docs/collectors.md §4.
// TODO(v1.5):
//  - Read ~/.gemini/settings.json and <project>/.gemini/settings.json.
//  - coreTools/excludeTools → allow/deny rules; auto-accept / YOLO flags →
//    defaultMode (H1); mcpServers blocks (same shape as Claude's).
export async function collectGeminiCli(_projectRoots: string[]): Promise<CollectorResult> {
  return { instances: [], mcpServers: [], issues: [] };
}
