#!/usr/bin/env node
/**
 * Systemores AI Agent & MCP Security Auditor — MCP Server & Cloud Bridge (v1.1.3)
 * Canonical URL: https://audit.systemores.com/api/mcp
 * Privacy Policy: https://audit.systemores.com/privacy (see PRIVACY.md)
 *
 * Exposes all 12 Systemores MCP 2026 diagnostic tools over stdio and proxies
 * authenticated tool executions over TLS to https://audit.systemores.com/api/mcp.
 */

import { createInterface } from "node:readline";
import { timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";

export const REMOTE_MCP_ENDPOINT = "https://audit.systemores.com/api/mcp";
export const PRIVACY_POLICY_URL = "https://audit.systemores.com/privacy";

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
      "Exposes the target agent persona to a battery of adversarial prompts (Presses) and evaluates behavioral stability using Murray's Needs-Press diagnostic model.",
    annotations: {
      title: "Stress Test Agent Persona",
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
  },
  {
    name: "systemores_evaluate_drift",
    title: "Evaluate Multi-Turn Behavioral Drift",
    description:
      "Simulates multiple conversational turns to evaluate agent output consistency and behavioral drift over extended interactions.",
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
          description: "The target agent's system prompt. Maximum 8,000 characters.",
        },
        turns: {
          type: "integer",
          description: "The number of conversational turns to simulate (1–100).",
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
  },
  {
    name: "systemores_assess_bias",
    title: "Assess Regulatory & Demographic Bias",
    description:
      "Verifies the agent's compliance with fair-lending, fair-housing, employment non-discrimination (EEOC/SIOP/ECOA), or child-directed safety (COPPA) standards.",
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
            "The underwriting, hiring, or housing agent system prompt to evaluate. Maximum 8,000 characters.",
        },
        complianceDomain: {
          type: "string",
          description:
            "The legal compliance framework to evaluate against (employment, housing, lending, or COPPA child safety).",
          enum: ["employment_eeoc", "housing_fair", "lending_ecoa", "children_coppa"],
        },
      },
      required: ["systemPrompt", "complianceDomain"],
    },
  },
  {
    name: "systemores_measure_drag",
    title: "Measure Cognitive Throughput Drag",
    description:
      "Measures operational latency, response length, and execution drag parameters to analyze cognitive throughput stability within the Behavioral OS ecosystem.",
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
          description: "The character length of the prompt sent to the agent.",
          minimum: 0,
        },
        responseLength: {
          type: "integer",
          description: "The character length of the agent's response.",
          minimum: 0,
        },
        latencyMs: {
          type: "number",
          description: "The end-to-end response latency in milliseconds. Must be >= 1.",
          minimum: 1,
        },
      },
      required: ["promptLength", "responseLength", "latencyMs"],
    },
  },
  {
    name: "systemores_tool_integrity",
    title: "Evaluate System Prompt Tool Discipline",
    description:
      "Evaluates whether the agent's system prompt establishes the behavioral conditions for safe, reliable tool use — auditing tool selection discipline, argument construction fidelity, and failure resilience when tool returns are ambiguous or erroneous.",
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
  },
  {
    name: "systemores_audit_tool_integrity",
    title: "Audit MCP Tool Definitions Integrity",
    description:
      "Audits the structural integrity, naming conventions, schema completeness, safety annotations, and injection surface of an AI agent's exposed tool definitions. Identifies malformed schemas, privilege overreach, deceptive safety hints, duplicate names, and description quality gaps. Operates entirely offline — no external API calls required.",
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
  },
  {
    name: "systemores_audit_agent_graph",
    title: "Audit Multi-Agent Execution Topology",
    description:
      "Statically scans multi-agent execution topologies (DAGs/meshes) using DFS algorithms to detect cyclic delegation loops and privilege escalation paths from public untrusted sub-agents to backend write/admin tools.",
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
            "JSON-serialized graph topology object containing 'nodes' (id, privilegeLevel) and 'edges' (source, target).",
        },
        maxDepth: {
          type: "integer",
          description: "Maximum depth to traverse during cycle and privilege path search.",
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
  },
  {
    name: "systemores_generate_cohort",
    title: "Generate Synthetic IPIP-NEO-120 Persona Cohort",
    description:
      "Generates statistical cohorts of synthetic user personas across enterprise operational domains with IPIP-NEO-120 30-facet psychometric profiles, demographic diversity, and prompt injection payloads.",
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
      },
      required: ["domain"],
    },
  },
  {
    name: "systemores_inject_environment_fault",
    title: "Generate Chaos Fault Injection Policy",
    description:
      "Configures dynamic chaos injection policies for tools, mock APIs, and databases during simulations (HTTP 429 rate limits, 500 errors, timeouts, 401 unauthorized, malformed JSON).",
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
          description: "The target tool name to attach fault injection policy to (or 'all_tools').",
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
  },
  {
    name: "systemores_analyze_trace_telemetry",
    title: "Analyze OpenTelemetry Agent Trace Spans",
    description:
      "Ingests standard OpenTelemetry (OTel) trace JSON payloads to detect financial token cost burn traps (> $2.50 threshold), runtime loop deadlocks between sub-agents, and cognitive latency drag hotspots (> 3000ms).",
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
          description: "JSON string containing OpenTelemetry trace spans or MCP telemetry log data.",
        },
        maxCostThresholdUsd: {
          type: "number",
          description:
            "Maximum allowable cost in USD per session before triggering burn trap alert.",
          default: 2.5,
        },
        latencyThresholdMs: {
          type: "integer",
          description: "Latency hotspot threshold in milliseconds.",
          default: 3000,
        },
      },
      required: ["otelTraceJson"],
    },
  },
  {
    name: "systemores_export_dossier",
    title: "Export Regulatory Compliance Dossier",
    description:
      "Aggregates findings from graph audits, synthetic cohort simulations, chaos tests, and trace analytics into formal compliance report packages for EU AI Act (EU 2024/1689), NIST AI RMF 1.0, EEOC/ECOA, and SOC 2 AI Addendums.",
    annotations: {
      title: "Export Regulatory Compliance Dossier",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: "object",
      properties: {
        auditSessionId: {
          type: "string",
          description: "Unique identifier for the completed audit session.",
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
      },
      required: ["auditSessionId"],
    },
  },
  {
    name: "systemores_audit_turn_live",
    title: "Live Turn Audit (Systemores System One)",
    description:
      "Performs real-time (~250ms) operational and behavioral turn auditing using Systemores System One. Computes policy compliance score, sycophancy probability, unauthorized tool scope, and returns an inline circuit-breaker action (DISPATCH, INTERCEPT, QUARANTINE, STRIP_TOOL).",
    annotations: {
      title: "Live Turn Audit (Systemores System One)",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
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
          description: "The proposed text response or output from the agent.",
        },
        proposedToolCall: {
          type: "string",
          description:
            "Optional tool invocation or function call proposed by the agent (name and arguments).",
        },
      },
      required: ["systemPrompt", "userMessage"],
    },
  },
];

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
    if (propSchema.type === "integer" && (!Number.isInteger(val) || typeof val !== "number")) {
      return { valid: false, error: `Parameter '${key}' must be an integer.` };
    }
    if (propSchema.type === "number" && (typeof val !== "number" || Number.isNaN(val))) {
      return { valid: false, error: `Parameter '${key}' must be a number.` };
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

  const response = await fetch(REMOTE_MCP_ENDPOINT, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: Date.now(),
      method: "tools/call",
      params: { name: toolName, arguments: args },
    }),
  });

  const payload = await response.json();
  if (payload.result) {
    return payload.result;
  }
  return {
    isError: true,
    content: [
      {
        type: "text",
        text: payload.error?.message || `Remote MCP error (HTTP ${response.status})`,
      },
    ],
  };
}

// ─── MCP SDK Static AST & Runtime Registration Bridge ────────────────────────
export const ListToolsRequestSchema = { method: "tools/list" };
export const CallToolRequestSchema = { method: "tools/call" };

export const server = {
  name: "systemores-plugin",
  version: "1.1.3",
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
  tools: TOOL_DEFINITIONS,
}));

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
        },
        serverInfo: {
          name: "systemores-plugin",
          version: "1.1.3",
        },
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
        tools: TOOL_DEFINITIONS,
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

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  startStdioServer();
}
