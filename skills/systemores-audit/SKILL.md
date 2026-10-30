---
name: systemores-audit
description: Audit AI agents, system prompts, MCP tool schemas, multi-agent delegation graphs, and OpenTelemetry traces using the Systemores 21-Dimension & IPIP-NEO-120 psychometric framework. Use when the user asks to stress-test an agent, check for sycophancy or behavioral drift, validate MCP tool security annotations, run a Systemores System One inline circuit-breaker check, or generate an EU AI Act / NIST AI RMF / SOC 2 compliance dossier.
---

# Systemores AI Agent Auditor Skill

Use this skill whenever the user wants to evaluate, stress-test, secure, or certify an AI agent, system prompt, MCP server, or multi-agent workflow.

## 1. Tool Matrix & Tier Availability

The Systemores MCP server (`systemores-cloud` or `systemores-agent-auditor`) exposes **11 specialized auditing tools** across three tiers:

### Free Community Tier ($0 / Zero-Config / Instant Execution)
These deterministic structural and efficiency tools run immediately upon plugin installation without requiring an API key:

| Tool Name | Purpose | Key Parameters |
| :--- | :--- | :--- |
| `systemores_audit_tool_integrity` | Audits MCP tool JSON definitions for prompt injection vectors, privilege overreach, and deceptive MCP 2026 `annotations` (`readOnlyHint`, `destructiveHint`). | `toolDefinitionsJson` (JSON array string), `strictMode` (`true` recommended) |
| `systemores_audit_agent_graph` | Analyzes multi-agent delegation topologies (`nodes` and `edges`) for infinite cyclic loops and `public -> admin` privilege escalation paths. | `graphTopologyJson` (JSON string), `maxDepth`, `strictPrivilegeCheck` |
| `systemores_measure_drag` | Computes cognitive drag, character-per-ms velocity, and token cost efficiency ratings. | `promptLength`, `responseLength`, `latencyMs` |

### Systemores Pro Tier ($49/mo — 1 Seat / 1,000 Audits/mo, or Trial Token)
These tools run live 30-adjective semantic extraction, Systemores 21-dimension scoring, IPIP-NEO-120 30-facet psychometrics, and sub-300ms Systemores System One inline circuit breaking:

| Tool Name | Purpose | Key Parameters |
| :--- | :--- | :--- |
| `systemores_audit_turn_live` | **Systemores System One** real-time (~250ms) circuit breaker. Returns `healthIndex` (0–100), calibrated sycophancy probability, information leakage verdict, and gate action (`DISPATCH`, `INTERCEPT`, `STRIP_TOOL`, `QUARANTINE`). | `systemPrompt`, `userMessage`, `agentResponse`, `proposedToolCall` |
| `systemores_stress_test_agent` | **Murray Needs-Press** adversarial stress test across 21 traits + derived Big Five (OCEAN), MBTI, and DISC profiles. | `systemPrompt`, `role` (`customer_support`, `financial_underwriter`, `medical_assistant`, `general_developer`), `pressIntensity` |
| `systemores_evaluate_drift` | Simulates multi-turn persona erosion and computes average drift index and deviation angle in degrees. | `systemPrompt`, `turns` (1–100), `temperature` |
| `systemores_assess_bias` | Evaluates algorithmic bias and regulatory non-compliance flags across protected domains. | `systemPrompt`, `complianceDomain` (`employment_eeoc`, `housing_fair`, `lending_ecoa`, `children_coppa`) |
| `systemores_generate_cohort` | Generates synthetic adversarial & baseline testing personas with full 30-facet IPIP-NEO-120 psychometric vectors. | `domain`, `cohortSize` (1–50), `includeAdversarial` |
| `systemores_analyze_trace_telemetry` | Inspects OpenTelemetry spans (with W3C `_meta.traceparent` support) for token burn traps, recursive tool deadlocks, and latency hotspots. | `otelTraceJson`, `maxCostThresholdUsd`, `latencyThresholdMs` |
| `systemores_inject_environment_fault` | Chaos engineering generator for testing agent resilience against HTTP 429s, 500s, timeouts, and malformed JSON. | `faultType`, `targetToolName`, `failureProbability` |

### Team & Compliance Tier ($199/mo — Multi-Seat CI/CD / 5,000 Audits/mo)
Includes everything in Pro plus multi-seat CI/CD licensing (up to 25 active IPs/24h), unredacted 21-trait covariance vectors, and formal regulatory certification dossiers:

| Tool Name | Purpose | Key Parameters |
| :--- | :--- | :--- |
| `systemores_export_dossier` | Generates a formal Markdown & JSON compliance certification dossier for **EU AI Act**, **NIST AI RMF 1.0**, **EEOC/ECOA**, and **SOC 2 Type II AI** (*Requires Team & Compliance or Enterprise tier*). | `auditSessionId`, `targetFrameworks`, `companyName` |

---

## 2. Recommended Audit Execution Sequence

1. **Discover Target Artifacts**:
   - Locate the project's system prompts, agent markdown definitions (`agents/*.md`, `GEMINI.md`, `AGENTS.md`), and MCP tool schemas (`tools.ts`, `mcp_config.json`, or route handlers).
2. **Run Free Structural Checks First**:
   - Always call `systemores_audit_tool_integrity` (with `strictMode: true`) on any discovered tool schemas and `systemores_audit_agent_graph` if multiple agents exist.
3. **Run Psychometric & Live Circuit-Breaker Checks**:
   - Call `systemores_stress_test_agent`, `systemores_evaluate_drift`, and `systemores_audit_turn_live` on the primary system prompt.
4. **Export Dossier or Remediation Diffs**:
   - Present the **Systemores Behavioral & Security Audit Scorecard** and offer drop-in prompt/schema fixes or a formal compliance dossier via `systemores_export_dossier`.

---

## 3. Configuring a Systemores Trial Token or Pro API Key

If the user is connected to `https://audit.systemores.com/api/mcp` without an API key and wants to unlock the Pro/Enterprise tools:

1. Direct them to **https://audit.systemores.com/pricing** to subscribe for an instant Pro/Team API key (`sys_pro_...`) or claim a 7-day Trial Token.
2. They can pass their token in their MCP configuration via `headers` (recommended so tokens are not logged in URL query strings):
   ```json
   {
     "mcpServers": {
       "systemores-cloud": {
         "serverUrl": "https://audit.systemores.com/api/mcp",
         "headers": {
           "Authorization": "Bearer YOUR_SYSTEMORES_API_KEY"
         }
       }
     }
   }
   ```
   Or via URL query parameter (`?trial_token=YOUR_SYSTEMORES_TOKEN`) if their MCP client does not support custom headers.
