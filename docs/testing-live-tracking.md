# Testing Guide — Live Permission Tracking

How to test the `/live` observed-activity feature locally, from a 30-second synthetic smoke test to a full session against real Claude Code. Architecture and rationale: `local/live-tracking-final-plan.md`; receiver controls: [security-architecture.md](security-architecture.md) §SR3a.

## Prerequisites

- `npm install && npm run dev` — dashboard **and** receiver share one server on `http://127.0.0.1:3000`.
- Open **http://127.0.0.1:3000/live**. With no events yet you should see the amber "No events received yet" notice containing the launch snippet. That empty state is itself the first check: receiver route advertised, no fake data.
- For Path 2: Claude Code ≥ 2.1.x installed (`claude --version`).

## Path 1 — Synthetic smoke test (no Claude Code needed)

From a second terminal, POST a minimal OTLP envelope with one accepted tool decision and its execution result:

```bash
curl -s -X POST -H 'content-type: application/json' \
  http://127.0.0.1:3000/api/otel/v1/logs -d '{
  "resourceLogs": [{"resource": {"attributes": [{"key":"service.version","value":{"stringValue":"2.1.229"}}]},
    "scopeLogs": [{"logRecords": [
      {"timeUnixNano":"1786700000000000000","attributes":[
        {"key":"event.name","value":{"stringValue":"tool_decision"}},
        {"key":"session.id","value":{"stringValue":"test-session-1"}},
        {"key":"event.sequence","value":{"intValue":"1"}},
        {"key":"tool_name","value":{"stringValue":"Bash"}},
        {"key":"tool_use_id","value":{"stringValue":"toolu_test1"}},
        {"key":"decision","value":{"stringValue":"accept"}},
        {"key":"source","value":{"stringValue":"config"}}]},
      {"timeUnixNano":"1786700001000000000","attributes":[
        {"key":"event.name","value":{"stringValue":"tool_result"}},
        {"key":"session.id","value":{"stringValue":"test-session-1"}},
        {"key":"event.sequence","value":{"intValue":"2"}},
        {"key":"tool_use_id","value":{"stringValue":"toolu_test1"}},
        {"key":"success","value":{"boolValue":true}},
        {"key":"duration_ms","value":{"intValue":"150"}}]}
    ]}]}]}'
```

**Expected:**

1. Response body reports `"accepted":2`.
2. Within 5 s (auto-refresh) the `/live` timeline shows a green **accept** row for `Bash` reading "executed in 150 ms", decision source `config`, confidence pill `vendor-event`.
3. The header notice flips to "Receiver active · last event just now".

**Dedup check:** run the identical command again. Response reports `"duplicates":2`, `"accepted":0`; the timeline must not grow.

**Rejection-path gate checks** (fixed error codes, no payload echo):

| Command variant | Expected |
|---|---|
| `--data '{broken'` | `400 {"error":"ERR_JSON_SYNTAX"}` |
| `-H 'content-type: text/plain'` | `415 {"error":"ERR_CONTENT_TYPE"}` |
| body > 2 MB | `413 {"error":"ERR_BODY_TOO_LARGE"}` |
| non-allowlisted event (e.g. `event.name: user_prompt`) | counted in `"ignored"`, never stored |

## Path 2 — Real Claude Code session

Launch Claude Code from a second terminal with telemetry directed at the receiver. This is a per-launch, user-directed opt-in — AgentLens never writes these settings (SR1):

```bash
CLAUDE_CODE_ENABLE_TELEMETRY=1 \
OTEL_METRICS_EXPORTER=none \
OTEL_LOGS_EXPORTER=otlp \
OTEL_TRACES_EXPORTER=none \
OTEL_EXPORTER_OTLP_LOGS_PROTOCOL=http/json \
OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://127.0.0.1:3000/api/otel/v1/logs \
OTEL_LOGS_EXPORT_INTERVAL=1000 \
OTEL_LOG_USER_PROMPTS=0 \
OTEL_LOG_ASSISTANT_RESPONSES=0 \
OTEL_LOG_TOOL_DETAILS=0 \
claude
```

Then exercise each evidence class and watch `/live` (rows should appear within ~5 s):

| Action in the Claude session | Expected timeline row |
|---|---|
| Ask it to run a command, **approve** the prompt | accept · source `user_temporary` (or `user_permanent` if you chose "don't ask again") · "executed in _n_ ms" |
| Ask for another command, **reject** it | reject · source `user_reject` · "not executed (rejected)" |
| Repeat an already-allowed command | accept · source `config` — Claude's evaluator decided without prompting |
| Press **Shift+Tab** to change permission mode | `mode change` · e.g. `default → acceptEdits` |
| Start in a project with MCP servers configured | `MCP server <name>: connected` rows at startup |
| Run two sessions in parallel | distinct short session ids; rows never mix sessions |

## Privacy verification (run after either path)

```bash
# Identity attributes and prompt text must never reach disk — empty output = pass
grep -rE 'user\.email|account_uuid|organization|prompt' data/observed/ ; echo "empty = pass"

# Secret patterns must not appear in stored events
grep -rE 'sk-[A-Za-z0-9]|AKIA|ghp_' data/observed/ ; echo "empty = pass"
```

With `OTEL_LOG_TOOL_DETAILS=0` (the default snippet), rows show tool *names* but no arguments — that is intended. Only enable detailed mode knowingly; tool arguments can contain secrets.

## Acceptance checklist (MVP subset)

- [ ] Decision visible on `/live` within 5 s of the action
- [ ] Accept and reject preserve their broad source category (`config`, `user_reject`, …)
- [ ] Accepted decision correlates to its result by `tool_use_id`; rejected calls never show as executed
- [ ] Duplicate deliveries produce no duplicate rows
- [ ] Malformed / oversized / wrong-type payloads rejected with fixed codes, no content echoed
- [ ] No identity attributes, prompt text, or secret patterns in `data/observed/`
- [ ] Receiver state (last-event age) and `vendor-event` confidence visible
- [ ] No row ever names a specific permission rule as the authorizer

The full acceptance matrix (concurrent-session ordering, exporter failure, hook-decided calls) lands as automated tests with hardening roadmap Step 4 / live-tracking phase L8.

## Reset & caveats

- `rm -rf data/observed` clears the timeline (gitignored; 7-day retention; per-day size cap).
- Events arrive only while the dashboard is running. Claude Code activity during receiver downtime is simply unobserved — which is exactly why the page states that absence of events is not proof of inactivity.
- Managed settings can constrain or redirect telemetry; if no data arrives under the documented snippet, check `claude` startup output rather than working around policy.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Empty state never clears in Path 2 | Telemetry env vars not applied to *that* launch (they are per-process); or managed policy overrides the exporter |
| `curl` gets connection refused | Dashboard not running, or a stale server owns the port — check `ss -tlnp \| grep 3000`, kill stale `next-server` processes, `rm -rf .next`, restart |
| Rows appear but "no execution result observed" | Normal for very recent accepts (result event lags), or the tool is still running |
| `"ignored"` count high, nothing stored | Exporter is sending non-permission events only — verify `OTEL_LOGS_EXPORTER=otlp` and the logs endpoint path `/api/otel/v1/logs` |
