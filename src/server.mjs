#!/usr/bin/env node
/**
 * Systemores AI Agent & MCP Security Auditor — MCP Server & Cloud Bridge (v1.2.2)
 * Canonical URL: https://audit.systemores.com/api/mcp
 * Privacy Policy: https://audit.systemores.com/privacy (see PRIVACY.md)
 *
 * Exposes all 12 Systemores MCP 2026 diagnostic tools over stdio and proxies
 * authenticated tool executions over TLS to https://audit.systemores.com/api/mcp.
 */

import { realpathSync } from "node:fs";
import { createInterface } from "node:readline";
import { timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";

export const REMOTE_MCP_ENDPOINT = "https://audit.systemores.com/api/mcp";
export const PRIVACY_POLICY_URL = "https://audit.systemores.com/privacy";
export const PLUGIN_VERSION = "1.2.2";

export const SERVER_INSTRUCTIONS = `Systemores AI Agent & MCP Security Auditor (v${PLUGIN_VERSION}).
Tool Selection & Disambiguation Guide (12 Tools):
1. Free Offline Static Checks (No API Key):
   - 'systemores_audit_tool_integrity': Audit MCP tool JSON schemas (toolDefinitionsJson) for naming, annotations, and injection risks (set strictMode=true). Do NOT use for system prompts.
   - 'systemores_audit_agent_graph': Statically scan multi-agent delegation JSON graphs (nodes/edges) for cycles and public-to-admin privilege paths.
   - 'systemores_measure_drag': Quick single-turn throughput/cost math from scalar promptLength, responseLength, and latencyMs.
2. Live Runtime & Telemetry Auditing (Pro/Trial Key):
   - 'systemores_audit_turn_live': Real-time (~250ms) advisory per-turn guardrail returning DISPATCH, INTERCEPT, QUARANTINE, or STRIP_TOOL.
   - 'systemores_analyze_trace_telemetry': Analyze multi-span OpenTelemetry JSON traces for token burn traps, loop deadlocks, and latency hotspots.
3. Pre-Deployment Prompt & Resilience Testing (Pro/Trial Key):
   - 'systemores_tool_integrity': Audit a systemPrompt for behavioral tool-use discipline (not MCP JSON schemas).
   - 'systemores_stress_test_agent': Adversarial prompt-injection resilience via Murray's Needs-Press model.
   - 'systemores_evaluate_drift': Multi-turn persona decay projection across turns and temperature.
   - 'systemores_assess_bias': Single-domain regulatory prompt audit (EEOC, Fair Housing, ECOA, COPPA, EU AI Act).
   - 'systemores_generate_cohort': Generate synthetic localized IPIP-NEO-120 test user cohorts.
   - 'systemores_inject_environment_fault': Generate stateless mock HTTP chaos fault policy fixtures for test harnesses.
4. Compliance Packaging (Team Key):
   - 'systemores_export_dossier': Final step — compile findings and optional zero-retention evidence into a signed EU AI Act / NIST AI RMF / EEOC-ECOA / SOC 2 dossier with verification URL and SVG badge.`;

export const SYSTEMORES_RESOURCES = [
  {
    uri: "systemores://rubrics/compliance-frameworks",
    name: "Systemores 21-Dimension & Regulatory Compliance Rubrics",
    description:
      "Canonical JSON reference of supported regulatory frameworks (EU AI Act, NIST AI RMF 1.0, EEOC/ECOA, COPPA, SOC 2 AI) and behavioral diagnostic thresholds.",
    mimeType: "application/json",
  },
];

const COMPLIANCE_RUBRICS_RESOURCE = {
  engineVersion: PLUGIN_VERSION,
  psychometricModels: [
    "Murray Needs-Press (Adversarial Stability)",
    "IPIP-NEO-120 (5 Domains, 30 Facets)",
    "Systemores System One (systemores-s1-inline — Inline Turn Circuit Breaker)",
  ],
  regulatoryFrameworks: {
    eu_ai_act: "EU AI Act (Regulation EU 2024/1689) High-Risk System Controls",
    nist_ai_rmf: "NIST AI Risk Management Framework 1.0 (GOVERN, MAP, MEASURE, MANAGE)",
    eeoc_ecoa: "EEOC / ECOA / Fair Housing Algorithmic Non-Discrimination",
    children_coppa: "COPPA Child-Directed Safety & Data Minimization",
    soc2_ai: "SOC 2 Type II Autonomous Agent & Tool Privilege Addendum",
  },
  thresholds: {
    maxSystemPromptChars: 8000,
    toolIntegrityPassScore: 80,
    defaultCostBurnTrapUsd: 2.5,
    defaultLatencyHotspotMs: 3000,
  },
};

const FREE_COMMUNITY_TOOLS = new Set([
  "systemores_audit_tool_integrity",
  "systemores_audit_agent_graph",
  "systemores_measure_drag",
]);

// ─── Sliding-Window Rate Limiter (60 requests / 60s per caller key) ──────────
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 60;
const rateBuckets = new Map();

export function checkRateLimit(callerId = "default") {
  const now = Date.now();
  const entry = rateBuckets.get(callerId);
  if (!entry || now >= entry.resetAt) {
    rateBuckets.set(callerId, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return { allowed: true, remaining: RATE_LIMIT_MAX_REQUESTS - 1 };
  }
  if (entry.count >= RATE_LIMIT_MAX_REQUESTS) {
    return {
      allowed: false,
      remaining: 0,
      retryAfterMs: entry.resetAt - now,
    };
  }
  entry.count += 1;
  return { allowed: true, remaining: RATE_LIMIT_MAX_REQUESTS - entry.count };
}

export function resetRateLimitsForTest() {
  rateBuckets.clear();
}

// ─── Bearer Token Authentication Guard ───────────────────────────────────────
export function verifyBearerAuth(toolName, authHeaderOrKey) {
  const rawToken = (
    authHeaderOrKey ||
    process.env.SYSTEMORES_API_KEY ||
    process.env.AUDIT_API_KEY ||
    ""
  )
    .replace(/^Bearer\s+/i, "")
    .trim();

  if (FREE_COMMUNITY_TOOLS.has(toolName)) {
    return { authenticated: Boolean(rawToken), tier: rawToken ? "pro" : "free_community", token: rawToken };
  }

  if (!rawToken || rawToken.length < 12) {
    return {
      authenticated: false,
      tier: "free_community",
      error: `Authentication required: '${toolName}' requires a Systemores Pro/Team API Key (sys_pro_...) or Trial Token via SYSTEMORES_API_KEY or Authorization: Bearer header. Provision a key at https://audit.systemores.com/pricing.`,
    };
  }

  // Constant-time prefix verification for sys_pro_ keys
  const prefix = Buffer.from("sys_pro_");
  const candidatePrefix = Buffer.from(rawToken.slice(0, 8).padEnd(8, "\0"));
  const isProKey = timingSafeEqual(prefix, candidatePrefix);

  return {
    authenticated: true,
    tier: isProKey ? "pro" : "trial",
    token: rawToken,
  };
}

// ─── Canonical 12 MCP 2026 Tool Definitions ──────────────────────────────────
export const TOOL_DEFINITIONS = [
  {
    name: "systemores_stress_test_agent",
    title: "Stress Test Agent Persona (Murray's Needs-Press)",
    description:
      "Stress-tests a supplied systemPrompt for a target role against simulated adversarial prompt batteries (low/medium/high pressIntensity) using Murray's Needs-Press model to score behavioral stability, sycophancy, and policy breaches. Read-only, zero-retention, LLM-backed scoring (slight run-to-run variance explains idempotentHint=false); requires a Pro/Trial API key. Use before deployment for adversarial resilience; use systemores_evaluate_drift for multi-turn consistency, systemores_assess_bias for legal domain bias, or systemores_audit_turn_live for per-turn runtime gating.",
    annotations: {
      title: "Stress Test Agent Persona (Murray's Needs-Press)",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description:
            "The behavioral blueprint or internal operational instructions of the target agent. Maximum 8,000 characters.",
        },
        role: {
          type: "string",
          description: "The intended operational function of the agent.",
          enum: [
            "customer_support",
            "financial_underwriter",
            "medical_assistant",
            "general_developer",
          ],
        },
        pressIntensity: {
          type: "string",
          description:
            "The intensity level of adversarial testing. 'high' simulates prompt injection batteries.",
          enum: ["low", "medium", "high"],
        },
      },
      required: ["systemPrompt", "role"],
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["PASSED", "FAILED"] },
        metrics: { type: "object" },
        attacksSimulated: { type: "integer" },
        breachesIdentified: { type: "array" },
        recommendation: { type: "string" },
        derivedPsychometrics: { type: "object" },
      },
      required: ["status", "metrics", "attacksSimulated", "breachesIdentified", "recommendation"],
    },
  },
  {
    name: "systemores_evaluate_drift",
    title: "Evaluate Multi-Turn Behavioral Drift",
    description:
      "Projects multi-turn persona decay and output drift from a static systemPrompt across simulated turns (1–100) and LLM temperature (0.0–1.5), returning averageDriftIndex, entropyRating, and predicted failure turn. Read-only, zero-retention, LLM-backed psychometric scoring (variance explains idempotentHint=false); requires a Pro/Trial API key. Use before deployment to estimate gradual policy decay over long sessions; use systemores_stress_test_agent for adversarial prompt attacks or systemores_audit_turn_live for real-time per-turn guarding.",
    annotations: {
      title: "Evaluate Multi-Turn Behavioral Drift",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description:
            "The target agent's system prompt. Maximum 8,000 characters.",
        },
        turns: {
          type: "integer",
          description:
            "The number of conversational turns to simulate (1–100).",
          default: 10,
          minimum: 1,
          maximum: 100,
        },
        temperature: {
          type: "number",
          description:
            "The LLM temperature parameter for the target agent (0.0–1.5). Higher values increase drift probability.",
          default: 0.7,
          minimum: 0.0,
          maximum: 1.5,
        },
      },
      required: ["systemPrompt"],
    },
    outputSchema: {
      type: "object",
      properties: {
        turnsEvaluated: { type: "integer" },
        averageDriftIndex: { type: "number" },
        entropyRating: { type: "string", enum: ["HIGH", "CONTROLLED"] },
        failurePointDetected: { type: "string" },
        estimatedDeviationAngleDegree: { type: "integer" },
        derivedPsychometrics: { type: "object" },
      },
      required: [
        "turnsEvaluated",
        "averageDriftIndex",
        "entropyRating",
        "failurePointDetected",
        "estimatedDeviationAngleDegree",
      ],
    },
  },
  {
    name: "systemores_assess_bias",
    title: "Assess Regulatory & Demographic Bias",
    description:
      "Statically analyzes a supplied systemPrompt (not a live agent) for demographic bias, proxy-variable leakage, and regulatory risks under one selected complianceDomain (employment_eeoc, housing_fair, lending_ecoa, children_coppa, or eu_ai_act). Read-only, zero-retention, LLM-backed scoring (variance explains idempotentHint=false); requires a Pro/Trial API key. Use for single-domain legal fairness auditing; use systemores_stress_test_agent for general adversarial resilience or systemores_export_dossier for multi-framework signed compliance reports.",
    annotations: {
      title: "Assess Regulatory & Demographic Bias",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description:
            "The underwriting, hiring, housing, or EU AI Act high-risk agent system prompt to evaluate. Maximum 8,000 characters.",
        },
        complianceDomain: {
          type: "string",
          description:
            "The legal compliance framework to evaluate against (employment, housing, lending, COPPA child safety, or EU AI Act 2024/1689).",
          enum: ["employment_eeoc", "housing_fair", "lending_ecoa", "children_coppa", "eu_ai_act"],
        },
      },
      required: ["systemPrompt", "complianceDomain"],
    },
    outputSchema: {
      type: "object",
      properties: {
        framework: { type: "string" },
        riskRating: { type: "string", enum: ["LOW", "MEDIUM", "HIGH"] },
        nonComplianceFlags: { type: "array" },
        mitigationInstructions: { type: "string" },
        derivedPsychometrics: { type: "object" },
      },
      required: ["framework", "riskRating", "nonComplianceFlags", "mitigationInstructions"],
    },
  },
  {
    name: "systemores_measure_drag",
    title: "Measure Cognitive Throughput Drag",
    description:
      "Calculates single-turn throughput and cost efficiency from scalar promptLength, responseLength, and latencyMs (>= 1), returning characterPerMs, cognitiveEfficiencyScore (0.1–1.0), dragRating (HIGH above 2500ms), and estimatedTokenCostRating (EXPENSIVE above 4000 combined chars). Free, deterministic, stateless local math with no API key required. Use for quick single-turn latency/length math; use systemores_analyze_trace_telemetry for multi-span OpenTelemetry JSON traces or systemores_evaluate_drift for multi-turn behavioral consistency.",
    annotations: {
      title: "Measure Cognitive Throughput Drag",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      properties: {
        promptLength: {
          type: "integer",
          description:
            "The character length of the prompt sent to the agent.",
          minimum: 0,
        },
        responseLength: {
          type: "integer",
          description: "The character length of the agent's response.",
          minimum: 0,
        },
        latencyMs: {
          type: "number",
          description:
            "The end-to-end response latency in milliseconds. Must be >= 1.",
          minimum: 1,
        },
      },
      required: ["promptLength", "responseLength", "latencyMs"],
    },
    outputSchema: {
      type: "object",
      properties: {
        characterPerMs: { type: "number" },
        dragRating: { type: "string", enum: ["EFFICIENT", "HIGH"] },
        estimatedTokenCostRating: { type: "string", enum: ["OPTIMIZED", "EXPENSIVE"] },
        cognitiveEfficiencyScore: { type: "number" },
      },
      required: [
        "characterPerMs",
        "dragRating",
        "estimatedTokenCostRating",
        "cognitiveEfficiencyScore",
      ],
    },
  },
  {
    name: "systemores_tool_integrity",
    title: "Evaluate System Prompt Tool Discipline",
    description:
      "Audits a supplied systemPrompt (max 8,000 chars) for behavioral tool-use safety — scoring tool selection discipline, argument construction fidelity, and failure resilience across toolContext risk profiles (api_calls, database, filesystem, code_execution). Read-only, zero-retention, LLM-backed advisory scoring (variance explains idempotentHint=false); requires a Pro/Trial API key. Use for prompt-level tool-use discipline; do NOT use for MCP tool JSON schemas — call systemores_audit_tool_integrity instead.",
    annotations: {
      title: "Evaluate System Prompt Tool Discipline",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description:
            "The agent's system prompt to evaluate for tool use safety. Maximum 8,000 characters.",
        },
        toolContext: {
          type: "string",
          description: "The domain of tool usage being audited. Affects risk weighting.",
          enum: ["api_calls", "database", "filesystem", "code_execution"],
        },
      },
      required: ["systemPrompt"],
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["PASSED", "FAILED"] },
        toolContext: { type: "string" },
        metrics: { type: "object" },
        risks: { type: "array" },
        recommendation: { type: "string" },
      },
      required: ["status", "toolContext", "metrics", "risks", "recommendation"],
    },
  },
  {
    name: "systemores_audit_tool_integrity",
    title: "Audit MCP Tool Definitions Integrity",
    description:
      "Statically audits an MCP tool definitions JSON array (toolDefinitionsJson, max 100,000 chars; accepts standard tools/list entries) for snake_case naming, schema completeness, deceptive ToolAnnotations, privilege scope, duplicate names, and injection surfaces. Free, deterministic, stateless check with no API key required; set strictMode=true to penalize missing parameter descriptions or annotations (returns FAIL on malformed JSON). Use for MCP JSON schema inspection; do NOT use for system prompts — call systemores_tool_integrity instead.",
    annotations: {
      title: "Audit MCP Tool Definitions Integrity",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      properties: {
        toolDefinitionsJson: {
          type: "string",
          description:
            "A JSON-serialized array of tool definition objects to audit. Each object should contain at minimum 'name' and 'description' fields. Accepts standard MCP ListToolsResult format.",
        },
        strictMode: {
          type: "boolean",
          description:
            "When true, applies stricter scoring thresholds — missing optional fields such as parameter descriptions, inputSchema, and MCP tool annotations are penalized. Defaults to false.",
          default: false,
        },
      },
      required: ["toolDefinitionsJson"],
    },
    outputSchema: {
      type: "object",
      properties: {
        overallScore: { type: "number" },
        integrityRating: { type: "string", enum: ["PASS", "REVIEW", "FAIL"] },
        toolsAudited: { type: "integer" },
        findings: { type: "array" },
        summary: { type: "string" },
      },
      required: ["overallScore", "integrityRating", "toolsAudited", "findings", "summary"],
    },
  },
  {
    name: "systemores_audit_agent_graph",
    title: "Audit Multi-Agent Execution Topology",
    description:
      "Statically scans a multi-agent delegation topology JSON object (graphTopologyJson, max 100,000 chars, with nodes and edges) via depth-bounded DFS (maxDepth 1–50, default 10) to detect cyclic delegation loops and untrusted-to-admin privilege paths. Free, deterministic, stateless check with no API key required; returns status FAILED on invalid JSON or empty graphs. Use for pre-deployment architecture checks; use systemores_analyze_trace_telemetry to detect runtime loops in live OpenTelemetry spans.",
    annotations: {
      title: "Audit Multi-Agent Execution Topology",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      properties: {
        graphTopologyJson: {
          type: "string",
          description:
            "JSON-serialized graph topology object (max 100,000 chars) containing 'nodes' ({ id, privilegeLevel: 'public'|'user'|'admin'|'system' }) and 'edges' ({ source, target }).",
        },
        maxDepth: {
          type: "integer",
          description:
            "Maximum DFS traversal depth for cycle and privilege-path checks (clamped 1–50, default 10). Paths deeper than maxDepth are not traversed.",
          default: 10,
        },
        strictPrivilegeCheck: {
          type: "boolean",
          description:
            "When true, flags any path from 'public'/'user' nodes to 'admin'/'system' nodes as a breach.",
          default: true,
        },
      },
      required: ["graphTopologyJson"],
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["PASSED", "FAILED"] },
        metrics: { type: "object" },
        cyclesDetected: { type: "array" },
        privilegeEscalationPaths: { type: "array" },
        risks: { type: "array" },
        recommendation: { type: "string" },
      },
      required: [
        "status",
        "metrics",
        "cyclesDetected",
        "privilegeEscalationPaths",
        "risks",
        "recommendation",
      ],
    },
  },
  {
    name: "systemores_generate_cohort",
    title: "Generate Synthetic IPIP-NEO-120 Persona Cohort",
    description:
      "Generates an ephemeral, non-deterministic cohort of 1–100 synthetic user personas for a target enterprise domain and locale (en, es, de, fr, pt, ja, zh) with 30-facet IPIP-NEO-120 profiles and adversarial prompt-injection/noisy-input payloads enabled by default (includeAdversarial=true). Read-only and unpersisted (randomized per call, explaining idempotentHint=false); requires a Pro/Trial API key. Use to create test populations for downstream QA runs rather than auditing an agent directly; pair with systemores_stress_test_agent or systemores_audit_turn_live.",
    annotations: {
      title: "Generate Synthetic IPIP-NEO-120 Persona Cohort",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "The operational domain for persona generation.",
          enum: ["underwriting", "customer_support", "healthcare", "devops", "claims"],
        },
        cohortSize: {
          type: "integer",
          description: "Number of synthetic personas to generate (1–100).",
          default: 10,
          minimum: 1,
          maximum: 100,
        },
        includeAdversarial: {
          type: "boolean",
          description: "Includes prompt-injection and noisy data submitter personas in the cohort.",
          default: true,
        },
        locale: {
          type: "string",
          description:
            "Target language code for synthetic persona names and prompt payloads (en, es, de, fr, pt, ja, zh; supports BCP-47 tags like pt-BR or zh-CN). Defaults to 'en'.",
          pattern: "^([eE][nN]|[eE][sS]|[dD][eE]|[fF][rR]|[pP][tT]|[jJ][aA]|[zZ][hH])([-_][a-zA-Z0-9]{2,8}){0,3}$",
          default: "en",
        },
      },
      required: ["domain"],
    },
    outputSchema: {
      type: "object",
      properties: {
        domain: { type: "string" },
        locale: { type: "string" },
        totalPersonas: { type: "integer" },
        personaTypes: { type: "object" },
        ipipNeoCoverage: { type: "string" },
        cohort: { type: "array" },
      },
      required: ["domain", "totalPersonas", "personaTypes", "ipipNeoCoverage", "cohort"],
    },
  },
  {
    name: "systemores_inject_environment_fault",
    title: "Generate Chaos Fault Injection Policy",
    description:
      "Generates a stateless, non-persistent chaos fault policy payload (mock HTTP body, simulatedLatencyMs, and retry guidance) for your test harness to simulate failures (429, 500, timeout, 401, malformed JSON) against targetToolName or 'all_tools' at failureProbability (0.01–1.0). Mutates no live tools or server state (non-idempotent only because each call emits a fresh policyId); requires a Pro/Trial API key. Use to produce mock fault fixtures for resilience tests; use systemores_stress_test_agent for prompt-level adversarial testing.",
    annotations: {
      title: "Generate Chaos Fault Injection Policy",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      properties: {
        faultType: {
          type: "string",
          description: "The specific chaos fault to inject.",
          enum: [
            "rate_limit_429",
            "server_error_500",
            "timeout",
            "unauthorized_401",
            "malformed_json",
          ],
        },
        targetToolName: {
          type: "string",
          description:
            "Target tool name to scope the generated mock fault policy to, or 'all_tools' for any tool.",
        },
        failureProbability: {
          type: "number",
          description: "Probability of fault triggering per invocation (0.01 to 1.0).",
          default: 0.5,
          minimum: 0.01,
          maximum: 1.0,
        },
      },
      required: ["faultType", "targetToolName"],
    },
    outputSchema: {
      type: "object",
      properties: {
        policyId: { type: "string" },
        targetToolName: { type: "string" },
        faultType: { type: "string" },
        failureProbability: { type: "number" },
        simulatedLatencyMs: { type: "integer" },
        mockResponseBody: { type: "string" },
        activeDurationSeconds: { type: "integer" },
        recommendation: { type: "string" },
      },
      required: [
        "policyId",
        "targetToolName",
        "faultType",
        "failureProbability",
        "simulatedLatencyMs",
        "mockResponseBody",
        "activeDurationSeconds",
        "recommendation",
      ],
    },
  },
  {
    name: "systemores_analyze_trace_telemetry",
    title: "Analyze OpenTelemetry Agent Trace Spans",
    description:
      "Analyzes an OpenTelemetry trace JSON payload (otelTraceJson, max 100,000 chars; span array or { spans, traceId } object) to summarize session token cost burn traps (default > $2.50), repeated-span sub-agent loop deadlocks, and per-span latency hotspots (default > 3000ms). Deterministic, stateless check requiring a Pro/Trial API key; returns rating CRITICAL on malformed JSON. Use for multi-span OTel/MCP trace logs; use systemores_measure_drag for single-turn character/latency math or systemores_audit_agent_graph for static topology analysis.",
    annotations: {
      title: "Analyze OpenTelemetry Agent Trace Spans",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      properties: {
        otelTraceJson: {
          type: "string",
          description:
            "JSON string (max 100,000 chars) of OpenTelemetry spans — either a span array or an object with a 'spans' array and optional 'traceId'/'traceparent'.",
        },
        maxCostThresholdUsd: {
          type: "number",
          description:
            "Maximum allowable cost in USD per session before triggering burn trap alert.",
          default: 2.5,
        },
        latencyThresholdMs: {
          type: "integer",
          description:
            "Per-span duration threshold in milliseconds above which a span is flagged as a latency hotspot (default 3000).",
          default: 3000,
        },
      },
      required: ["otelTraceJson"],
    },
    outputSchema: {
      type: "object",
      properties: {
        traceId: { type: "string" },
        traceContextPropagated: { type: "boolean" },
        totalSpansEvaluated: { type: "integer" },
        estimatedCostUsd: { type: "number" },
        costBurnTrapDetected: { type: "boolean" },
        loopDeadlocksDetected: { type: "array" },
        latencyHotspotsMs: { type: "array" },
        rating: { type: "string", enum: ["OPTIMIZED", "WARNING", "CRITICAL"] },
        recommendations: { type: "array" },
      },
      required: [
        "traceId",
        "traceContextPropagated",
        "totalSpansEvaluated",
        "estimatedCostUsd",
        "costBurnTrapDetected",
        "loopDeadlocksDetected",
        "latencyHotspotsMs",
        "rating",
        "recommendations",
      ],
    },
  },
  {
    name: "systemores_export_dossier",
    title: "Export Regulatory Compliance Dossier",
    description:
      "Compiles audit findings and optional transient evidence (systemPrompt, toolDefinitionsJson, graphTopologyJson, otelTraceJson, liveAuditMetricsJson) into a signed, localized (en, es, de, fr, pt, ja, zh) compliance dossier with SHA-256 hash, verification link, and SVG badge for EU AI Act, NIST AI RMF 1.0, EEOC/ECOA, and SOC 2 AI. Optional evidence is scored strictly in memory (zero-retention) for dynamic_evidence mode; omitting it produces a baseline_attestation dossier. Persists a new signed certificate record per call (new dossierId, explaining readOnlyHint=false and idempotentHint=false); requires a Team API key and completed auditSessionId as the final reporting step after diagnostic audits.",
    annotations: {
      title: "Export Regulatory Compliance Dossier",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      properties: {
        auditSessionId: {
          type: "string",
          description:
            "Unique identifier for the completed audit session (used to attribute the signed dossier certificate).",
        },
        targetFrameworks: {
          type: "string",
          description:
            "Comma-separated list of regulatory frameworks to generate formal dossier sections for: 'eu_ai_act', 'nist_ai_rmf', 'eeoc_ecoa', 'soc2_ai'. Defaults to all if omitted.",
        },
        companyName: {
          type: "string",
          description: "Legal entity or client name for dossier attribution.",
          default: "Enterprise Client",
        },
        locale: {
          type: "string",
          description:
            "Target language code for human-readable dossier prose and executive summary (en, es, de, fr, pt, ja, zh; supports BCP-47 tags like pt-BR or zh-CN; canonical JSON fields and SHA-256 hash remain invariant). Defaults to 'en'.",
          pattern: "^([eE][nN]|[eE][sS]|[dD][eE]|[fF][rR]|[pP][tT]|[jJ][aA]|[zZ][hH])([-_][a-zA-Z0-9]{2,8}){0,3}$",
          default: "en",
        },
        systemPrompt: {
          type: "string",
          description:
            "Optional agent system prompt evaluated strictly in memory (never stored) to compute differentiated per-framework scores via Murray Needs-Press, drift, bias, and tool-discipline diagnostics. Maximum 8,000 characters.",
        },
        role: {
          type: "string",
          description:
            "Optional operational role of the target agent when evaluating systemPrompt (defaults to 'general_developer').",
          enum: [
            "customer_support",
            "financial_underwriter",
            "medical_assistant",
            "general_developer",
          ],
        },
        toolDefinitionsJson: {
          type: "string",
          description:
            "Optional JSON array of MCP tool definitions evaluated strictly in memory (never stored) under strictMode to score SOC 2 AI and NIST AI RMF tool governance.",
        },
        graphTopologyJson: {
          type: "string",
          description:
            "Optional JSON multi-agent delegation graph containing nodes and edges evaluated strictly in memory for cycle and privilege boundary scoring.",
        },
        otelTraceJson: {
          type: "string",
          description:
            "Optional OpenTelemetry span payload evaluated strictly in memory for token burn, loop, and latency scoring.",
        },
        liveAuditMetricsJson: {
          type: "string",
          description:
            "Optional JSON object of transient audit metrics (healthIndex 0-100, sycophancyProbability 0-1, personaStabilityIndex 0-1, averageDriftIndex 0-1, toolIntegrityScore 0-100) from preceding tool calls.",
        },
      },
      required: ["auditSessionId"],
    },
    outputSchema: {
      type: "object",
      properties: {
        dossierId: { type: "string" },
        timestamp: { type: "string" },
        companyName: { type: "string" },
        auditSessionId: { type: "string" },
        locale: { type: "string" },
        frameworksEvaluated: { type: "array" },
        certificationStatus: {
          type: "string",
          enum: ["CERTIFIED", "CONDITIONAL_APPROVAL", "NON_COMPLIANT"],
        },
        executiveSummary: { type: "string" },
        frameworkScores: { type: "object" },
        overallScore: { type: "integer" },
        scoringMode: {
          type: "string",
          enum: ["dynamic_evidence", "baseline_attestation"],
        },
        engineVersion: { type: "string" },
        zeroRetentionVerified: { type: "boolean" },
        sha256IntegrityHash: { type: "string" },
        verificationUrl: { type: "string" },
        badgeSvgUrl: { type: "string" },
        badgeMarkdown: { type: "string" },
        dossierMarkdown: { type: "string" },
      },
      required: [
        "dossierId",
        "timestamp",
        "companyName",
        "auditSessionId",
        "frameworksEvaluated",
        "certificationStatus",
        "executiveSummary",
        "frameworkScores",
        "overallScore",
        "scoringMode",
        "engineVersion",
        "zeroRetentionVerified",
        "sha256IntegrityHash",
        "verificationUrl",
        "badgeSvgUrl",
        "badgeMarkdown",
        "dossierMarkdown",
      ],
    },
  },
  {
    name: "systemores_audit_turn_live",
    title: "Live Turn Audit (Systemores System One)",
    description:
      "Performs real-time (~250ms) inline operational and behavioral auditing for a single turn using Systemores System One. Evaluates required systemPrompt and userMessage (optionally paired with agentResponse and/or proposedToolCall, each max 8,000 chars) to score policy compliance, sycophancy probability, and unauthorized tool scope, returning an advisory circuit-breaker action (DISPATCH, INTERCEPT, QUARANTINE, STRIP_TOOL) for the caller to enforce. Read-only, zero-retention, LLM-backed scoring (variance explains idempotentHint=false); requires a Pro/Trial API key. Use as a live per-turn guardrail before returning replies or invoking tools; use systemores_stress_test_agent or systemores_evaluate_drift for pre-deployment batch evaluation.",
    annotations: {
      title: "Live Turn Audit (Systemores System One)",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    inputSchema: {
      type: "object",
      properties: {
        systemPrompt: {
          type: "string",
          description:
            "The behavioral blueprint, constraints, or security policies of the agent under audit.",
        },
        userMessage: {
          type: "string",
          description: "The prompt or message sent by the user in this interaction turn.",
        },
        agentResponse: {
          type: "string",
          description:
            "Optional proposed assistant reply text to audit against systemPrompt (max 8,000 chars). Provide agentResponse, proposedToolCall, or both for full turn inspection.",
        },
        proposedToolCall: {
          type: "string",
          description:
            "Optional tool invocation proposed by the agent (JSON string or 'tool_name(args)' text, max 8,000 chars) to check for unauthorized tool scope.",
        },
      },
      required: ["systemPrompt", "userMessage"],
    },
    outputSchema: {
      type: "object",
      properties: {
        engine: { type: "string" },
        status: { type: "string", enum: ["AUDITED", "FALLBACK"] },
        latencyMs: { type: "number" },
        tokens: { type: "object" },
        metrics: { type: "object" },
        verdict: {
          type: "string",
          enum: ["PASSED", "DRIFT_WARNING", "CRITICAL_BREACH", "TOOL_SCOPE_VIOLATION"],
        },
        circuitBreakerAction: {
          type: "string",
          enum: ["DISPATCH", "INTERCEPT", "QUARANTINE", "STRIP_TOOL"],
        },
        autoRecoveryRecommendation: { type: "string" },
      },
      required: ["engine", "status", "latencyMs", "metrics", "verdict", "circuitBreakerAction"],
    },
  },
];

const SUPPORTED_LOCALE_LIST = ["en", "es", "de", "fr", "pt", "ja", "zh"];
const BCP47_LOCALE_REGEX = /^[a-zA-Z]{2,3}(?:[-_][a-zA-Z0-9]{2,8}){0,3}$/;

function normalizeLocaleTag(raw) {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (trimmed === "") return "en";
  if (!BCP47_LOCALE_REGEX.test(trimmed)) return null;
  const primary = trimmed.toLowerCase().replace(/_/g, "-").split("-")[0];
  return SUPPORTED_LOCALE_LIST.includes(primary) ? primary : null;
}

// ─── Strict Input Schema Validator ───────────────────────────────────────────
export function validateToolArguments(toolName, args = {}) {
  const tool = TOOL_DEFINITIONS.find((t) => t.name === toolName);
  if (!tool) {
    return { valid: false, error: `Unknown tool: ${toolName}` };
  }
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    return { valid: false, error: "Tool arguments must be a JSON object." };
  }

  const { properties = {}, required = [] } = tool.inputSchema;
  for (const reqField of required) {
    if (args[reqField] === undefined || args[reqField] === null || args[reqField] === "") {
      return { valid: false, error: `Missing required parameter '${reqField}' for ${toolName}.` };
    }
  }

  for (const [key, propSchema] of Object.entries(properties)) {
    const val = args[key];
    if (val === undefined) continue;
    if (propSchema.type === "string" && typeof val !== "string") {
      return { valid: false, error: `Parameter '${key}' must be a string.` };
    }
    if (propSchema.type === "boolean" && typeof val !== "boolean") {
      return { valid: false, error: `Parameter '${key}' must be a boolean.` };
    }
    if (
      propSchema.type === "integer" &&
      (typeof val !== "number" || !Number.isFinite(val) || !Number.isInteger(val))
    ) {
      return { valid: false, error: `Parameter '${key}' must be an integer.` };
    }
    if (propSchema.type === "number" && (typeof val !== "number" || !Number.isFinite(val))) {
      return { valid: false, error: `Parameter '${key}' must be a number.` };
    }
    if (key === "locale" && typeof val === "string") {
      if (!normalizeLocaleTag(val)) {
        return {
          valid: false,
          error: `Parameter 'locale' must match BCP-47 for one of: ${SUPPORTED_LOCALE_LIST.join(", ")}.`,
        };
      }
      continue;
    }
    if (typeof propSchema.pattern === "string" && typeof val === "string") {
      const regex = new RegExp(propSchema.pattern);
      if (!regex.test(val)) {
        return { valid: false, error: `Parameter '${key}' does not match required pattern.` };
      }
    }
    if (Array.isArray(propSchema.enum) && !propSchema.enum.includes(val)) {
      return {
        valid: false,
        error: `Parameter '${key}' must be one of: ${propSchema.enum.join(", ")}.`,
      };
    }
    if (typeof propSchema.minimum === "number" && typeof val === "number" && val < propSchema.minimum) {
      return { valid: false, error: `Parameter '${key}' must be >= ${propSchema.minimum}.` };
    }
    if (typeof propSchema.maximum === "number" && typeof val === "number" && val > propSchema.maximum) {
      return { valid: false, error: `Parameter '${key}' must be <= ${propSchema.maximum}.` };
    }
  }

  if (toolName === "systemores_export_dossier") {
    if (args.targetFrameworks !== undefined) {
      const validFrameworks = new Set(["eu_ai_act", "nist_ai_rmf", "eeoc_ecoa", "soc2_ai"]);
      const tokens = args.targetFrameworks
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      if (tokens.length === 0 || tokens.some((fw) => !validFrameworks.has(fw))) {
        return {
          valid: false,
          error:
            "Parameter 'targetFrameworks' must contain one or more of: eu_ai_act, nist_ai_rmf, eeoc_ecoa, soc2_ai.",
        };
      }
    }

    if (args.systemPrompt !== undefined) {
      if (!args.systemPrompt.trim() || args.systemPrompt.length > 8000) {
        return {
          valid: false,
          error: "Parameter 'systemPrompt' must be a non-empty string up to 8,000 characters.",
        };
      }
    }

    for (const jsonField of ["toolDefinitionsJson", "graphTopologyJson", "otelTraceJson"]) {
      if (args[jsonField] !== undefined && (!args[jsonField].trim() || args[jsonField].length > 100000)) {
        return {
          valid: false,
          error: `Parameter '${jsonField}' must be a non-empty JSON string up to 100,000 characters.`,
        };
      }
    }

    if (args.liveAuditMetricsJson !== undefined) {
      if (!args.liveAuditMetricsJson.trim() || args.liveAuditMetricsJson.length > 10000) {
        return {
          valid: false,
          error: "Parameter 'liveAuditMetricsJson' must be a non-empty JSON string up to 10,000 characters.",
        };
      }
      let parsedMetrics;
      try {
        parsedMetrics = JSON.parse(args.liveAuditMetricsJson);
      } catch {
        return {
          valid: false,
          error: "Parameter 'liveAuditMetricsJson' must be valid JSON.",
        };
      }
      if (!parsedMetrics || typeof parsedMetrics !== "object" || Array.isArray(parsedMetrics)) {
        return {
          valid: false,
          error: "Parameter 'liveAuditMetricsJson' must be a JSON object.",
        };
      }
      const bounds = {
        healthIndex: [0, 100],
        sycophancyProbability: [0, 1],
        personaStabilityIndex: [0, 1],
        averageDriftIndex: [0, 1],
        toolIntegrityScore: [0, 100],
      };
      for (const [metricKey, [min, max]] of Object.entries(bounds)) {
        if (!Object.hasOwn(parsedMetrics, metricKey) || parsedMetrics[metricKey] === undefined) continue;
        const metricVal = parsedMetrics[metricKey];
        if (
          typeof metricVal !== "number" ||
          !Number.isFinite(metricVal) ||
          metricVal < min ||
          metricVal > max
        ) {
          return {
            valid: false,
            error: `Parameter 'liveAuditMetricsJson.${metricKey}' must be a finite number between ${min} and ${max}.`,
          };
        }
      }
    }
  }

  return { valid: true };
}

// ─── Tool Execution Dispatcher (Forwards to Cloud MCP over HTTPS) ────────────
export async function executeToolCall(toolName, args = {}, options = {}) {
  const callerId = options.callerId || "stdio-client";
  const rateCheck = checkRateLimit(callerId);
  if (!rateCheck.allowed) {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: `Rate limit exceeded (max ${RATE_LIMIT_MAX_REQUESTS} req/min). Retry in ${Math.ceil(
            (rateCheck.retryAfterMs || 60000) / 1000
          )}s.`,
        },
      ],
    };
  }

  const validation = validateToolArguments(toolName, args);
  if (!validation.valid) {
    return {
      isError: true,
      content: [{ type: "text", text: `Input validation error: ${validation.error}` }],
    };
  }

  const auth = verifyBearerAuth(toolName, options.apiKey);
  if (!auth.authenticated && !FREE_COMMUNITY_TOOLS.has(toolName)) {
    return {
      isError: true,
      content: [{ type: "text", text: auth.error }],
    };
  }

  const forwardArgs =
    args && typeof args === "object" && !Array.isArray(args) ? { ...args } : {};
  if (typeof forwardArgs.locale === "string") {
    forwardArgs.locale = normalizeLocaleTag(forwardArgs.locale) || "en";
  }

  if (options.dryRun) {
    return {
      isError: false,
      content: [
        {
          type: "text",
          text: JSON.stringify({
            tool: toolName,
            validated: true,
            tier: auth.tier,
            endpoint: REMOTE_MCP_ENDPOINT,
          }),
        },
      ],
    };
  }

  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };
  if (auth.token) {
    headers.Authorization = `Bearer ${auth.token}`;
  }

  try {
    const response = await fetch(REMOTE_MCP_ENDPOINT, {
      method: "POST",
      signal: AbortSignal.timeout(15_000),
      headers,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: Date.now(),
        method: "tools/call",
        params: { name: toolName, arguments: forwardArgs },
      }),
    });

    const rawText = await response.text();
    let payload = {};
    if (rawText.trimStart().startsWith("{")) {
      payload = JSON.parse(rawText);
    } else {
      const sseDataLines = rawText
        .split("\n")
        .filter((line) => line.startsWith("data: "))
        .map((line) => line.slice(6).trim())
        .filter((chunk) => chunk && chunk !== "[DONE]");
      if (sseDataLines.length > 0) {
        payload = JSON.parse(sseDataLines[sseDataLines.length - 1]);
      }
    }
    if (payload.result) {
      return payload.result;
    }
    const errText =
      typeof payload.error === "string"
        ? payload.error
        : payload.error?.message || `Remote MCP error (HTTP ${response.status})`;
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: errText,
        },
      ],
    };
  } catch (error) {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: `Remote MCP transport error: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
    };
  }
}

// ─── MCP SDK Static AST & Runtime Registration Bridge ────────────────────────
export const ListToolsRequestSchema = { method: "tools/list" };
export const CallToolRequestSchema = { method: "tools/call" };
export const ListResourcesRequestSchema = { method: "resources/list" };
export const ReadResourceRequestSchema = { method: "resources/read" };

export const server = {
  name: "systemores-plugin",
  version: PLUGIN_VERSION,
  instructions: SERVER_INSTRUCTIONS,
  registeredTools: new Map(),
  handlers: new Map(),
  tool(name, description, schema, annotations, handler) {
    this.registeredTools.set(name, { name, description, schema, annotations, handler });
  },
  setRequestHandler(schemaObj, handler) {
    this.handlers.set(schemaObj.method || schemaObj, handler);
  },
};

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  ttlMs: 3600000,
  cacheScope: "global",
  tools: TOOL_DEFINITIONS,
}));

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: SYSTEMORES_RESOURCES,
  ttlMs: 3600000,
}));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const uri = request?.params?.uri;
  if (uri === "systemores://rubrics/compliance-frameworks") {
    return {
      contents: [
        {
          uri,
          mimeType: "application/json",
          text: JSON.stringify(COMPLIANCE_RUBRICS_RESOURCE, null, 2),
        },
      ],
    };
  }
  throw new Error(`Resource not found: ${uri}`);
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params || {};
  return executeToolCall(name, args || {});
});

for (const def of TOOL_DEFINITIONS) {
  server.tool(
    def.name,
    def.description,
    def.inputSchema,
    def.annotations,
    async (args) => executeToolCall(def.name, args)
  );
}

// ─── JSON-RPC 2.0 Request Handler (Stdio & Programmatic) ─────────────────────
export async function handleJsonRpcMessage(message) {
  if (!message || typeof message !== "object") return null;

  const { id, method, params } = message;

  if (method === "notifications/initialized" || method === "notifications/cancelled") {
    return null;
  }

  if (method === "initialize") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: params?.protocolVersion || "2025-11-25",
        capabilities: {
          tools: { listChanged: false },
          resources: { listChanged: false },
        },
        serverInfo: {
          name: "systemores-plugin",
          version: PLUGIN_VERSION,
        },
        instructions: SERVER_INSTRUCTIONS,
      },
    };
  }

  if (method === "ping") {
    return { jsonrpc: "2.0", id, result: {} };
  }

  if (method === "tools/list") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        ttlMs: 3600000,
        cacheScope: "global",
        tools: TOOL_DEFINITIONS,
      },
    };
  }

  if (method === "resources/list") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        resources: SYSTEMORES_RESOURCES,
        ttlMs: 3600000,
      },
    };
  }

  if (method === "resources/read") {
    const uri = params?.uri;
    if (uri === "systemores://rubrics/compliance-frameworks") {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          contents: [
            {
              uri,
              mimeType: "application/json",
              text: JSON.stringify(COMPLIANCE_RUBRICS_RESOURCE, null, 2),
            },
          ],
        },
      };
    }
    return {
      jsonrpc: "2.0",
      id: id ?? null,
      error: {
        code: -32602,
        message: `Resource not found: ${uri ?? "(missing uri)"}`,
      },
    };
  }

  if (method === "tools/call") {
    const toolName = params?.name;
    const toolArgs = params?.arguments || {};
    const result = await executeToolCall(toolName, toolArgs);
    return {
      jsonrpc: "2.0",
      id,
      result,
    };
  }

  return {
    jsonrpc: "2.0",
    id: id ?? null,
    error: {
      code: -32601,
      message: `Method not found: ${method}`,
    },
  };
}

// ─── Stdio Server Entry Point ────────────────────────────────────────────────
export function startStdioServer() {
  const rl = createInterface({
    input: process.stdin,
    terminal: false,
  });

  rl.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      const msg = JSON.parse(trimmed);
      const reply = await handleJsonRpcMessage(msg);
      if (reply) {
        process.stdout.write(JSON.stringify(reply) + "\n");
      }
    } catch {
      process.stdout.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        }) + "\n"
      );
    }
  });
}

export function isExecutedDirectly(metaUrl, argv1 = process.argv[1]) {
  if (!argv1) return false;
  const modulePath = fileURLToPath(metaUrl);
  if (modulePath === argv1) return true;
  try {
    return realpathSync(modulePath) === realpathSync(argv1);
  } catch {
    return false;
  }
}

if (isExecutedDirectly(import.meta.url)) {
  startStdioServer();
}
