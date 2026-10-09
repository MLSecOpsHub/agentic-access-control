import type {
  AgentInstance,
  McpServer,
  RiskFinding,
  ThreatScenario,
} from "./schema";
import { CATALOG } from "./scenario-catalog";

export interface RunScenariosCtx {
  instances: AgentInstance[];
  mcpServers: McpServer[];
  findings: RiskFinding[];
}

export function runScenarios(ctx: RunScenariosCtx): ThreatScenario[] {
  const scenarios: ThreatScenario[] = [];
  for (const inst of ctx.instances) {
    for (const entry of CATALOG) {
      const scenario = entry.evaluate(inst, ctx);
      if (scenario) scenarios.push(scenario);
    }
  }
  return scenarios;
}
