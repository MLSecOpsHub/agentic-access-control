// The Claude Code OpenTelemetry launch environment that points a session's
// permission events at AgentLens's loopback receiver (docs/testing-live-tracking.md).
// Used to render the snippet on /live and by the QA launcher to start a child
// `claude` process. AgentLens never writes these settings anywhere: they apply
// to one explicitly launched process only (SR1/SR3). Privacy-first defaults:
// no prompts, no responses, no tool arguments.

export function claudeOtelEnv(endpoint: string): Record<string, string> {
  return {
    CLAUDE_CODE_ENABLE_TELEMETRY: "1",
    OTEL_METRICS_EXPORTER: "none",
    OTEL_LOGS_EXPORTER: "otlp",
    OTEL_TRACES_EXPORTER: "none",
    OTEL_EXPORTER_OTLP_LOGS_PROTOCOL: "http/json",
    OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: endpoint,
    OTEL_LOGS_EXPORT_INTERVAL: "1000",
    OTEL_LOG_USER_PROMPTS: "0",
    OTEL_LOG_ASSISTANT_RESPONSES: "0",
    OTEL_LOG_TOOL_DETAILS: "0",
  };
}

export function renderLaunchSnippet(endpoint: string): string {
  return [...Object.entries(claudeOtelEnv(endpoint)).map(([k, v]) => `${k}=${v} \\`), "claude"].join("\n");
}
