# AI Agent Access Control — Landscape Map
### Commercial products & open-source tools that govern what an AI agent can reach
**Compiled 3 August 2026.** All GitHub stats and M&A/funding claims independently verified in a second pass; corrections noted inline.

---

## 0. How to read this

"Access control for AI agents" is three different products wearing one name. Buying or building in the wrong layer is the most common mistake in this market.

| Layer | What it does | Who it's for | Enforcement real? |
|---|---|---|---|
| **L0 — Native platform controls** | Vendor's own permission system (Claude Code permissions, Entra Agent ID, Workspace AI control center) | Everyone; free/bundled | Yes, but only inside that vendor's walls |
| **L1 — In-path gateways & sandboxes** | Sits between agent and resource; intercepts the actual tool call | Enterprises + self-hosting individuals | **Yes — this is the only layer that literally blocks** |
| **L2 — Identity governance & posture** | Discovers agents, maps permissions, scores risk, certifies access | Enterprise IAM/GRC teams | Mostly *observe*; enforcement usually delegated back to L0/L1 |

**The single most important finding:** most vendors marketing "AI agent access control" are L2. They tell you an agent is over-permissioned; they don't stop it. Only L1 (and native L0) sit in the request path. When evaluating anything below, ask: *does this product see the tool call before it executes, or does it read logs afterward?*

A second structural point: **the enforcement point differs per agent↔resource pair.** There is no single product covering all of your examples. Claude→local filesystem is an OS-sandbox problem. Gemini→Drive is a Workspace admin-console problem. Claude→AWS is an MCP-gateway/IAM problem. See the scenario matrix in §4.

---

## 1. Layer 0 — Native controls (check these before buying anything)

| Platform | Control | Granularity | Admin-enforceable? | Status |
|---|---|---|---|---|
| **Claude Code** | Permission rules `deny → ask → allow`; modes incl. `plan`, `acceptEdits`, `bypassPermissions` | Per-command glob, per-path, per-domain, per-MCP-tool | Yes, via managed settings | GA |
| **Claude Code** | OS sandbox (Seatbelt/bubblewrap) for Bash — filesystem + network egress | Path + hostname allowlist | Yes (`sandbox.enabled`, `allowUnsandboxedCommands:false`) | GA — macOS/Linux/WSL2, **no native Windows** |
| **Claude** | Managed MCP (`managed-mcp.json`), `allowedMcpServers`/`deniedMcpServers` | Per-server by URL/command | Yes | GA. ⚠️ Anthropic states `serverName` matching is *"not a security control"* — spoofable |
| **Claude Enterprise** | Audit Log + Compliance API (announced Mar 30 2026) | Admin/resource events | Yes | GA. ⚠️ **Excludes inference/chat content entirely** |
| **AWS** | Bedrock AgentCore Identity — inbound (SigV4/JWT) + outbound (OAuth token vault, 2LO/3LO) | Per-scope, per-workload-identity | Yes | GA (Oct 13 2025); OBO token exchange added Apr 2026 |
| **AWS** | IAM condition keys for AgentCore | ⚠️ **VPC placement only** — no condition key governs in-session tool/data access | Yes | GA |
| **AWS** | CloudTrail for Gateway | API-call level | Yes | ⚠️ **Data events off by default** |
| **Microsoft** | **Entra Agent ID** — directory identity per agent, Conditional Access, human sponsor model, Entitlement Management | Per-agent, per-resource | Yes | **GA April 2026** — the most mature cross-platform native offering |
| **Microsoft** | Purview DSPM for AI (covers Copilot + 3rd-party AI via browser ext) | Prompt/response DLP | Yes | GA, but ⚠️ **audit-mode by default**, block is opt-in with user override |
| **Microsoft** | SharePoint Restricted Content Discovery | Site-level hide-from-Copilot | Yes | GA. ⚠️ **Does not change underlying permissions** |
| **Google** | Workspace AI control center — "Allow Gemini access to Workspace data" | ⚠️ Coarse binary toggle per OU/config group | Yes | GA May 4 2026 (Enterprise Standard/Plus) |
| **Google** | Gemini Enterprise Agent Identity (SPIFFE-format IDs) + Agent Gateway + Model Armor | Per-agent IAM + semantic policy | Yes | **Core Agent Identity GA Jun 25 2026**; *auth-manager credential broker still Preview* |
| **Google** | GKE Agent Sandbox (gVisor) | Blocks hostNetwork/hostPath/metadata egress | Yes | GA |
| **OpenAI** | ChatGPT Enterprise connector/app controls | Per-app, per-action (all/read-only/custom), field-level params | Yes | GA — **apps disabled by default** |
| **OpenAI** | Codex sandboxing (Seatbelt/bwrap+seccomp/Windows sandbox) | Network off by default, domain allowlist | Yes, `requirements.toml` | GA |

**Universal native gaps (vendor-acknowledged):**
1. **Network egress allowlisting is hostname-only and TLS-blind everywhere** — Anthropic's own docs flag domain fronting as unresolved.
2. **The MCP authorization spec explicitly excludes stdio transport** ("SHOULD NOT follow this spec") — and stdio is the dominant real-world deployment. Most actual MCP traffic sits outside all the OAuth machinery.
3. **No cross-cloud agent identity interop** — AWS, Microsoft, and Google each built an incompatible primitive.
4. **Content-level audit of agent reasoning/tool I/O is non-default or absent** on every platform.

---

## 2. Layer 1 — Open source on GitHub (the buildable layer)

⭐ counts verified 3 Aug 2026.

### 2a. MCP gateways / proxies — authz + audit in the request path

| Repo | ⭐ | License | Status | What it enforces |
|---|---|---|---|---|
| [octelium/octelium](https://github.com/octelium/octelium) | 3.9k | AGPL-3.0 / Apache-2.0 client | active | Self-hosted zero-trust plane: ZTNA + API/AI/MCP gateway. Broadest scope here |
| [IBM/mcp-context-forge](https://github.com/IBM/mcp-context-forge) | 3.7k | Apache-2.0 | active | Federating registry/proxy for MCP + A2A + REST/gRPC with governance & observability. **Most complete enterprise OSS option** |
| [agentgateway/agentgateway](https://github.com/agentgateway/agentgateway) | 3.4k | Apache-2.0 | active | Envoy-lineage agentic proxy; token exchange isolates per-tool perms, tool-poisoning/rug-pull defense. Solo.io → **Linux Foundation** |
| [stacklok/toolhive](https://github.com/stacklok/toolhive) | 2.0k | Apache-2.0 | active | Runs MCP servers in locked-down containers + authz CRD. Best sandbox+policy combo |
| [envoyproxy/ai-gateway](https://github.com/envoyproxy/ai-gateway) | 1.8k | Apache-2.0 | active | Envoy/CNCF unified auth layer for gen-AI services |
| [docker/mcp-gateway](https://github.com/docker/mcp-gateway) | 1.4k | MIT | active | Containerized MCP servers, 1CPU/2GB caps, no host FS unless explicitly mounted, secrets blocked, image signing |
| [agentic-community/mcp-gateway-registry](https://github.com/agentic-community/mcp-gateway-registry) | 649 | Apache-2.0 | active | OAuth via Keycloak/Entra/Okta/Auth0 + discovery + audit. AWS-blogged |
| [microsoft/mcp-gateway](https://github.com/microsoft/mcp-gateway) | 634 | MIT | active, no releases | K8s session-aware routing/lifecycle. Early-stage |
| [luckyPipewrench/pipelock](https://github.com/luckyPipewrench/pipelock) | 577 | Apache-2.0 / Elastic-2.0 | active | **Agent firewall** — inspects MCP/HTTP/A2A/WS for exfiltration, SSRF, prompt injection; signed audit receipts |
| [mozilla-ai/mcpd](https://github.com/mozilla-ai/mcpd) | 167 | Apache-2.0 | active | Declarative MCP server config daemon |
| [provnai/McpVanguard](https://github.com/provnai/McpVanguard) | 12 | MIT | active | Inspect/block risky tool calls pre-execution + audit evidence. Tiny but on-thesis |
| [open-webui/mcpo](https://github.com/open-webui/mcpo) | 4.2k | MIT | ⚠️ stale ~5mo | MCP → OpenAPI/REST bridge (passthrough, not policy) |
| [lasso-security/mcp-gateway](https://github.com/lasso-security/mcp-gateway) | 371 | MIT | ⚠️ stale ~7mo | Plugin-based guardrails/monitoring |
| [eqtylab/mcp-guardian](https://github.com/eqtylab/mcp-guardian) | 199 | Apache-2.0 | ⚠️ **abandoned ~16mo** | Human-approval gates + message logging |
| [centralmind/gateway](https://github.com/centralmind/gateway) | 541 | Apache-2.0 | ⚠️ **stale ~13mo** | DB→MCP with data-scoping. *Correction: an earlier pass misdated this as current — last commit Jul 2025* |

**Discovery index:** [e2b-dev/awesome-mcp-gateways](https://github.com/e2b-dev/awesome-mcp-gateways) (133⭐)

### 2b. Sandboxing / filesystem + network confinement — this is the answer for "Claude → local filesystem"

| Repo | ⭐ | License | Status | Notes |
|---|---|---|---|---|
| [firecracker-microvm/firecracker](https://github.com/firecracker-microvm/firecracker) | 34.7k | Apache-2.0 | active | AWS microVM — the substrate under most agent sandboxes |
| [apple/container](https://github.com/apple/container) | 26.5k | Apache-2.0 | active | Linux containers as light VMs on Apple silicon |
| [google/gvisor](https://github.com/google/gvisor) | 18.5k | Apache-2.0 | active | Userspace kernel; powers GKE Agent Sandbox |
| [e2b-dev/e2b](https://github.com/e2b-dev/e2b) | 12.9k | Apache-2.0 | active | Firecracker cloud sandboxes for agent-generated code |
| [superradcompany/microsandbox](https://github.com/superradcompany/microsandbox) | 7.1k | Apache-2.0 | active | Local-first microVM, ~200ms boot, "every agent gets its own machine" |
| **[anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)** | **4.6k** | Apache-2.0 | active | **OS-level FS + network sandboxing for agent processes, no container.** First-party, most directly on-point for local agents |
| [dagger/container-use](https://github.com/dagger/container-use) | 3.8k | Apache-2.0 | commits active, release ~1yr stale | Git-branch-isolated containerized agent workspaces |
| [coder/boundary](https://github.com/coder/boundary) | 21 | MIT | active | Lightweight Linux egress restriction via namespaces + proxy |

### 2c. Scanners & posture

| Repo | ⭐ | Status | Notes |
|---|---|---|---|
| [snyk/agent-scan](https://github.com/snyk/agent-scan) | 2.9k | active | **⚠️ Formerly `invariantlabs-ai/mcp-scan` — repo moved after Snyk acquired Invariant Labs (Jun 2025); old URL redirects.** Scans MCP servers/configs/skills for tool poisoning |
| [harishsg993010/damn-vulnerable-MCP-server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) | 1.3k | moderate | Deliberately vulnerable MCP server, 10 challenges |
| [slowmist/MCP-Security-Checklist](https://github.com/slowmist/MCP-Security-Checklist) | 829 | ⚠️ stale ~15mo | Checklist framework |
| [Puliczek/awesome-mcp-security](https://github.com/Puliczek/awesome-mcp-security) | 698 | active to Mar 2026 | Curated research/tools/incidents index |
| [riseandignite/mcp-shield](https://github.com/riseandignite/mcp-shield) | ~556 | low | Tool-poisoning / exfil / cross-origin escalation scanner |

### 2d. Policy engines & identity substrate

| Repo | ⭐ | MCP-native integration? |
|---|---|---|
| [casbin/casbin](https://github.com/casbin/casbin) | 20.3k | No |
| [open-policy-agent/opa](https://github.com/open-policy-agent/opa) | 11.8k | No first-party |
| [authzed/spicedb](https://github.com/authzed/spicedb) | 6.8k | No |
| [Permify/permify](https://github.com/Permify/permify) | 5.9k | No |
| [openfga/openfga](https://github.com/openfga/openfga) | 5.2k | No |
| [cedar-policy/cedar](https://github.com/cedar-policy/cedar) | 1.5k | No first-party repo (used inside AWS AgentCore, Natoma) |
| [permitio/permit-fastmcp](https://github.com/permitio/permit-fastmcp) | 17 | **Yes** — ⚠️ but stale since Sep 2025 |
| [spiffe/spire](https://github.com/spiffe/spire) | 2.4k | Substrate — Google's Agent Identity uses SPIFFE format |
| [keycloak/keycloak](https://github.com/keycloak/keycloak) | 34.7k | Used as OAuth IdP by several MCP gateways |
| [mcpauth/mcpauth](https://github.com/mcpauth/mcpauth) | 113 | **Yes** — self-hostable OAuth 2.0 for MCP |
| ⚠️ [hashicorp/vault](https://github.com/hashicorp/vault) | 35.7k | **BUSL-1.1 — not OSI open source since 2023** |

> **The clearest whitespace in the entire landscape:** mature authz engines (OPA, Cedar, OpenFGA, SpiceDB, Permify, Casbin — ~50k combined stars) have **essentially zero first-party MCP/agent integration.** The only ones that exist are Permit.io's, at 3–17 stars and stale. Authz-engine-rich, MCP-glue-poor.

### 2e. Individual/user-side — control over your own Claude Code / Cursor / Gemini CLI

Almost entirely hobby-grade. This is the thinnest part of the market.

| Repo | ⭐ | What it does |
|---|---|---|
| [karanb192/claude-code-hooks](https://github.com/karanb192/claude-code-hooks) | 455 | Installable hook marketplace: safety, cost tracking, observability |
| [delexw/claude-code-trace](https://github.com/delexw/claude-code-trace) | 321 | Renders session JSONL as conversations, MCP-call detection, live tail |
| [textcortex/spritz](https://github.com/textcortex/spritz) | 95 | K8s-native agent control plane (successor to archived `claude-code-sandbox`) |
| [kornysietsma/claude-code-permissions-hook](https://github.com/kornysietsma/claude-code-permissions-hook) | 36 | PreToolUse hook, granular allow/deny/pattern-match |
| [Tonyhzk/cc-permission-manager](https://github.com/Tonyhzk/cc-permission-manager) | 30 | Desktop GUI for permission configs |
| [l-mb/claude-code-redaction-hooks](https://github.com/l-mb/claude-code-redaction-hooks) | 18 | Blocks/redacts secrets & PII before they reach the model or leave via tool output |
| [scadastrangelove/agent-audit](https://github.com/scadastrangelove/agent-audit) | 15 | Forensic auditor for local agent logs (Claude Code, Codex CLI); 296 rules |
| [schmitthub/clawker](https://github.com/schmitthub/clawker) | 16 | Claude Code in isolated Docker behind egress firewall |

---

## 3. Layer 1–2 — Commercial

### 3a. In-path MCP/agent gateways (real enforcement)

| Vendor | Mechanism | Notes |
|---|---|---|
| **[Cloudflare MCP Server Portals](https://blog.cloudflare.com/zero-trust-mcp-server-portals/)** | Cloudflare One SASE, Access/OAuth-gated per server & tool | **Open beta, free up to 50 seats** — best free on-ramp |
| **[Teleport MCP Access](https://goteleport.com/use-cases/secure-model-context-protocol/)** | Identity proxy, short-lived per-request creds, RBAC+ABAC, JIT, session recording | Customers: Nasdaq, Discord, Airtable, Elastic. "Beams" agent runtime still **beta** |
| **[Pomerium](https://www.pomerium.com/docs/capabilities/mcp)** | Reverse proxy + PPL policy language, full request logging | Explicitly names Claude, ChatGPT, VS Code as clients. Has OSS core |
| **[Kong AI Gateway](https://konghq.com/solutions/mcp-governance)** | API gateway plugin | **Publishes pricing**: Plus per-gateway/mo + $100/mo per unique LLM model |
| **[Solo.io Enterprise agentgateway](https://www.solo.io/blog/introducing-solo-enterprise-for-agentgateway)** | Envoy ambient proxy | Commercial distro of the LF OSS project; cryptographically verifiable audit trails |
| **[MintMCP](https://www.mintmcp.com/)** | Reverse proxy, curated catalog, per-agent identities | SOC 2 Type II. Customers: Coursera, Harvey AI |
| **[Lunar.dev MCPX](https://www.lunar.dev/product/mcp)** | Docker gateway, RBAC, immutable audit, DLP add-on | OSS core + enterprise |
| **[Obot AI](https://obot.ai/enterprise-mcp-governance/)** | Proxy/control plane, egress control, per-user/team policy | OSS free + paid enterprise |
| **[Natoma](https://natoma.ai/platform)** | Cedar ABAC middleware; demoed hard denial | **Acquired by Snowflake, announced May 27 2026** |
| **[Salt Security MCP Finder](https://salt.security/)** | Discovery + blocking **via AWS WAF** | Real enforcement, **AWS-only** |
| **[Docker MCP Toolkit](https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/)** | Local containerization | Free in Docker Desktop |
| **[Descope](https://www.descope.com/pricing)** | OAuth 2.1 authorization server for MCP | Issues tokens; **your server must enforce scopes** — not itself in-path. Free tier 7,500 MAU |
| ⚠️ **Smithery** | Registry + hosting | **No authz/audit claims found** — marketplace, not governance |

### 3b. Enterprise agent identity & access governance

**Now GA and credible:**

| Vendor | What's differentiated | Status |
|---|---|---|
| **[Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id)** | Directory object per agent; Conditional Access; **human sponsor auto-transfers to their manager on departure**; federates to AWS Bedrock + n8n | **GA Apr 2026.** Benchmark to beat |
| **[Okta for AI Agents](https://www.okta.com/solutions/secure-ai/) + [Cross App Access](https://www.okta.com/identity-101/cross-app-access-securing-ai-agent-and-app-to-app-connections/)** | IdP as OAuth token broker; XAA is an IETF draft co-authored with Ping | **GA Apr 29 2026**; XAA protocol still draft |
| **[Auth0 for AI Agents](https://auth0.com/ai)** | Token Vault (35+ APIs), **async authorization via CIBA** for human-in-the-loop, FGA for RAG permission-filtering | GA Nov 19 2025. Free tier |
| **[Aembit](https://aembit.io/)** | Secretless credential exchange; full OAuth 2.1 MCP authorization server; **"blended identity"** (agent + human operator evaluated together) | **GA Apr 9 2026.** ⭐ **One of only two vendors publishing pricing: free / $20 per agent/mo / enterprise** |
| **[Arcade.dev](https://www.arcade.dev/)** | Action runtime; **permission-intersection enforcement** (agent ∩ delegated user); token vault isolated from LLM context | $60M raised Jun 15 2026. Air-gapped/self-host options |
| **[Palo Alto Idira](https://www.paloaltonetworks.com/idira/agentic)** | Discovery → registry → JIT broker → **"Agent Kill Switch"** | Launched May 12 2026 on acquired CyberArk tech. ⚠️ No named customers yet |
| **[Saviynt](https://saviynt.com/)** | Access Gateway does runtime authz (inspects execution plan → allow/block/limit/escalate); covers Bedrock, Copilot Studio, Vertex, ServiceNow, Agentforce | Design partners: Hertz, UKG, Auto Club Group. **$700M @ ~$3B, KKR-led** |
| **[Silverfort](https://www.silverfort.com/platform/ai-agent-security/)** | Agentless discovery via IdP/cloud APIs; "Storyline" permission-chain graphs; enforces via own MCP Gateway or native Copilot Studio hooks | Acquired Fabrix Security 2026 |
| **[Obsidian Security](https://www.obsidiansecurity.com/ai-agent-security)** | Evidence-based least-privilege from *actual* usage, not claimed need. Covers Bedrock, **Claude**, Vertex, Copilot, n8n, OpenAI, Agentforce | Strongest named-customer list: T-Mobile, Databricks, S&P Global, Snowflake, Seagate |
| **[Token Security](https://www.token.security/)** | NHI discovery incl. on-prem/hybrid; shipped its own MCP server | $20M Series A. Customers: HiBob, Udemy, Elastic, Klaviyo, Lemonade |

**Not yet shipping — do not count on these:**
- **BeyondTrust AI Agent Security** — private beta only, **US GA targeted Fall 2026**. (Notable when it lands: vendor-agnostic policy across Claude Code, GitHub Copilot, Cursor.)
- **ConductorOne AI Access Management** — "early preview with select customers." $79M Series B.
- **Teleport Beams** — beta.
- **Oak** — $60M seed, exited stealth Jul 15 2026 (founders Shai Morag/Tal Marom, prior exits Secdo→PANW, Ermetic→Tenable $265M). Zero named customers.

**Repackaged — be skeptical:**
- **Wiz AI-SPM**, **Upwind**, **Sysdig** — CNAPP posture/eBPF monitoring relabeled. Explicitly observe-only. (Sysdig does name Claude Code and Gemini coding-agent monitoring, Mar 2026 — but detects, doesn't gate.)
- **Reco**, **Nudge Security** — SSPM/shadow-IT discovery relabeled "shadow AI."
- **GitGuardian** — secrets scanning extending into NHI narrative. $50M Series C Feb 2026.
- **Knostic** — vendor states outright it is *"not about blocking access"*; it reshapes/redacts LLM answers.
- **Britive** — active agentic content push but **no funding round since Series B, March 2023** — likely a Cloud PAM reposition.
- **Corsha** — genuine machine identity, but OT/industrial + federal focus, not LLM-agent-to-SaaS.

### 3c. Runtime AI security & usage governance (adjacent — mostly DLP/CASB lineage)

Real enforcement, but at the browser/network edge rather than inside the tool call: **Netskope**, **Zscaler** (AI Broker, announced Jun 2026, no GA/pricing), **Island**, **Cyberhaven** (⚠️ its own Chrome extension was supply-chain compromised Dec 2024), **Harmonic Security** ("coach, don't block").

AI-native runtime: **Zenity** (Gartner's "Company to Beat" in AI agent governance, Apr 2026 — but confirmed inline enforcement is **M365 Copilot only**), **Noma Security** ($132M total), **WitnessAI** ($58M), **Straiker** ($64M Series A), **Lasso Security**, **HiddenLayer**, **Pillar Security**.

**Prompt Security (SentinelOne)** deserves a specific callout: one of the very few L2-lineage vendors with a genuine **MCP Gateway** intercepting calls to 13,000+ known MCP servers with real-time redaction/blocking.

---

## 4. Scenario matrix — your exact examples

| Scenario | Where enforcement actually lives | Best OSS | Best commercial |
|---|---|---|---|
| **Claude → AWS resources** | MCP gateway in front of the AWS MCP server, **or** AWS-side IAM/AgentCore Identity | IBM ContextForge, agentgateway, ToolHive | Teleport, Cloudflare Portals, Aembit, Salt (AWS WAF) |
| **Claude → local filesystem** | **OS sandbox on the machine** — no IAM product reaches here | **anthropic-experimental/sandbox-runtime**, microsandbox, clawker, coder/boundary | Docker MCP Toolkit (free); BeyondTrust *when it GAs* |
| **Gemini → Google Drive** | **Google Workspace admin console only.** Third parties can't intercept the Gemini↔Drive API call | — (no OSS reaches this) | Workspace AI control center (native) + Drive Labels/DLP; Obsidian/Zenity for visibility |
| **Copilot → M365** | Microsoft Purview DLP + Entra Agent ID + SharePoint RCD | — | Purview (native, audit-mode default); Zenity (only place its inline enforcement is confirmed); Knostic for answer-shaping |
| **ChatGPT connectors** | OpenAI Enterprise admin console (per-app, per-action, field-level) | — | Native controls are genuinely good here — apps off by default |
| **Custom/in-house agents** | Your own gateway | ContextForge, agentgateway, ToolHive, pipelock | Arcade.dev, Aembit, Auth0 for AI Agents, Descope |

---

## 5. Market structure

**Consolidation has been violent — 13 acquisitions in ~16 months.** Almost every pure-play named a year ago is now inside a platform vendor.

| Target | Acquirer | Price | Date |
|---|---|---|---|
| Wiz | Google | $32B | Closed Mar 11 2026 |
| CyberArk | Palo Alto Networks | ~$25B | Announced Jul 30 2025, closed ~Feb 12 2026 |
| Oasis Security | Cyera | $1B | Announced Jul 28 2026 (pending) |
| SGNL | CrowdStrike | ~$740M | Jan 8 2026 |
| Protect AI | Palo Alto Networks | ~$500–700M (reported) | Apr 2025 |
| Astrix Security | Cisco | ⚠️ **Undisclosed** — reported $250M–$400M, sources conflict | Announced May 4, closed Jun 29 2026 |
| Aim Security | Cato Networks | ~$350–400M (reported) | Sep 3 2025 |
| Lakera | Check Point | ~$300M (reported) | Sep 16 2025 |
| CalypsoAI | F5 | $180M | Sep 2025 |
| Entro Security | SailPoint | Undisclosed (sources conflict badly) | Closed Jun 29 2026 |
| Natoma | Snowflake | Undisclosed | Announced May 27 2026 |
| Prompt Security | SentinelOne | Undisclosed | Aug 5 2025 |
| Invariant Labs | Snyk | Undisclosed | Jun 24 2025 |

**Still independent:** Token Security, Clutch, Britive, Veza, P0, Andromeda, Linx, Unosecur, Descope, WorkOS, Stytch, Arcade.dev, ConductorOne, Teleport, Oak, Zenity, Obsidian, Silverfort, Saviynt, Noma, WitnessAI, Straiker, HiddenLayer, Lasso, Knostic, MintMCP, Lunar.dev, Operant, Obot.

**Pricing opacity is near-total.** Of ~60 commercial vendors surveyed, only **Aembit**, **Kong**, **Descope**, and partially **Stytch/Zapier** publish prices. Everything else is contact-sales. Klavis AI's G2 listing explicitly confirms no public pricing anywhere.

---

## 6. Standards status (all still moving)

| Standard | Status |
|---|---|
| **MCP Authorization** (OAuth 2.1 + RFC 9728 PRM + RFC 8707 resource indicators + CIMD) | Draft track. ⚠️ **stdio transport explicitly out of scope** |
| **IETF ID-JAG / Cross-App Access** (Okta+Ping authors) | draft-04, May 21 2026, expires Nov 22 2026. **Not an RFC** |
| **A2A v1.0** | Auth fully delegated to OAuth2/OIDC/API keys in Agent Card. No built-in agent-identity verification beyond bearer-token possession |
| **SPIFFE/SPIRE** | Mature CNCF; now the substrate under Google's Agent Identity |
| **OWASP Top 10 for Agentic Applications** | Published Dec 9 2025. ASI03 = Identity & Privilege Abuse. **The most concrete artifact to sell/build against today** |
| **NIST NCCoE** agent identity/authz | Initial public draft only; comments closed ~Apr 2 2026. **No finalized SP** — a real gap for regulated buyers |
| **OpenID AuthZEN** AARP + COAZ (MCP tool-authz ↔ AuthZEN mapping) | Pre-standard working drafts |

---

## 7. Where the whitespace is

1. **Policy-engine ↔ MCP glue.** ~50k stars of mature authz engines with no first-party agent integration. The one existing bridge (Permit.io) is 17 stars and stale.
2. **Individual/prosumer tooling.** Nearly the entire commercial market is enterprise sales-motion. The user-side OSS category tops out at 455 stars of hobby hooks. Nobody has built the "Little Snitch for AI agents."
3. **stdio MCP authorization.** The spec disclaims it; the deployments use it. Nobody owns this.
4. **TLS-aware egress control.** Every vendor and every native control allowlists by hostname and is blind to domain fronting — Anthropic says so in its own docs.
5. **Cross-vendor agent identity.** Three incompatible cloud primitives, one expired-in-November IETF draft, no NIST reference architecture.
6. **Content-level agent audit.** Every platform's audit log excludes the inference/tool-I/O content that actually matters for incident response.

---

## 8. Verification notes

Corrections applied after an adversarial second pass:
- **Cisco/Astrix $400M** — not primary-confirmed. Cisco disclosed no price; reports range $250M–$400M. Quote as a range.
- **Google Gemini Agent Identity** — earlier pass said "Preview." Core feature went **GA Jun 25 2026**; only the auth-manager credential broker remains Preview.
- **`invariantlabs-ai/mcp-scan`** — repo silently moved to **`snyk/agent-scan`** post-acquisition.
- **`centralmind/gateway`** — earlier pass misread a 2024 release date as 2026, making a 13-month-dormant repo look current.
- **Noma $100M Series B** — Jul 31 2025, not 2026.

Unverified / needs manual re-check: OpenAI AgentKit Connector Registry GA status (doc URL 404'd during research); funding totals for Obot AI, Lunar.dev, Operant AI.
