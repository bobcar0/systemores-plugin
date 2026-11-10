# Privacy Policy — Systemores AI Agent & MCP Security Auditor

**Effective Date:** October 30, 2026  
**Publisher:** Systemores LLC (`https://systemores.com` / `https://audit.systemores.com`)  
**Canonical Privacy Policy URL:** https://audit.systemores.com/privacy

## 1. Overview & Data Minimization

Systemores LLC ("Systemores", "we", "our") provides the **Systemores AI Agent & MCP Security Auditor** plugin and Model Context Protocol (MCP) server (`https://audit.systemores.com/api/mcp`). We adhere strictly to **Privacy by Design** and data minimization principles:

- **No Training on Customer Prompts or Code:** Systemores never uses your system prompts, MCP tool schemas, multi-agent graph topologies, or OpenTelemetry traces to train foundation models.
- **Ephemeral Diagnostic Processing:** Prompts, tool schemas, and agent turn payloads submitted to the Systemores Cloud MCP Server are processed ephemerally in memory solely to compute psychometric stability scores, inline circuit-breaker verdicts, and regulatory compliance dossiers.
- **Zero-Knowledge API Key Storage:** Pro and Team API keys (`sys_pro_...`) are hashed using SHA-256 (`createHash("sha256")`) prior to storage. Raw API keys are never persisted at rest.

## 2. Information Processed by Tier

### Free Community Tier (Static & Structural Tools)
- Tools: `systemores_audit_tool_integrity`, `systemores_audit_agent_graph`, `systemores_measure_drag`
- Payloads (`toolDefinitionsJson`, `graphTopologyJson`, latency integers) are evaluated deterministically and discarded immediately upon returning the JSON response.
- Client IP addresses are processed solely for sliding-window burst rate limiting.

### Pro & Team Cloud Tiers (Psychometric, Live Circuit-Breaker & Compliance Tools)
- Tools: `systemores_stress_test_agent`, `systemores_evaluate_drift`, `systemores_assess_bias`, `systemores_tool_integrity`, `systemores_generate_cohort`, `systemores_inject_environment_fault`, `systemores_analyze_trace_telemetry`, `systemores_export_dossier`, `systemores_audit_turn_live`
- **Authentication & Licensing Metadata:** We store a SHA-256 digest of your API key, subscription tier (`pro`, `team`, `enterprise`), billing status via Stripe, aggregate monthly call counts, and a rolling 24-hour set of distinct client IPs to enforce seat licensing.

## 3. Third-Party Subprocessors

- **Vercel Inc.** — Serverless edge hosting and TLS termination.
- **Upstash Inc.** — Encrypted Redis storage for SHA-256 hashed API key metadata and rate-limit counters.
- **Stripe Inc.** — PCI-DSS Level 1 compliant subscription billing. Systemores never receives or stores payment card numbers.

## 4. Security & Contact

All MCP communication is encrypted in transit via HTTPS (TLS 1.3). For privacy inquiries, data deletion requests, or security disclosures, contact:

- **Email:** support@systemores.com
- **Web:** https://audit.systemores.com/privacy
