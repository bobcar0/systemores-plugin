#!/usr/bin/env node
/**
 * Systemores Plugin Structure & Manifest Verification Script
 * Verifies Antigravity (plugin.json), Claude Code (.claude-plugin/plugin.json),
 * Gemini CLI (gemini-extension.json), MCP config, subagent, skill, rules, and logo assets.
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");

const ALLOWED_PLUGIN_JSON_KEYS = new Set([
  "name",
  "description",
  "logo",
  "suggestedPrompts",
  "displayName",
  "version",
  "author",
  "homepage",
  "repository",
  "disabled",
]);

let passed = 0;
let failed = 0;

function assert(label, condition, detail = "") {
  if (condition) {
    console.log(`  ✅ ${label}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL: ${label}${detail ? ` (${detail})` : ""}`);
    failed++;
  }
}

console.log("🔍 Verifying Systemores Plugin Bundle...\n");

// 1. Verify plugin.json
const pluginJsonPath = path.join(rootDir, "plugin.json");
assert("plugin.json exists", fs.existsSync(pluginJsonPath));
const pluginJson = JSON.parse(fs.readFileSync(pluginJsonPath, "utf-8"));
assert("plugin.json name is 'systemores'", pluginJson.name === "systemores");
assert("plugin.json has non-empty description", typeof pluginJson.description === "string" && pluginJson.description.length > 20);
assert("plugin.json has exactly 3 suggestedPrompts", Array.isArray(pluginJson.suggestedPrompts) && pluginJson.suggestedPrompts.length === 3);
const unknownKeys = Object.keys(pluginJson).filter((k) => !ALLOWED_PLUGIN_JSON_KEYS.has(k));
assert("plugin.json contains only allowed top-level fields", unknownKeys.length === 0, `unknown keys: ${unknownKeys.join(", ")}`);

// 2. Verify logo asset
const logoPath = path.join(rootDir, pluginJson.logo);
assert(`logo file exists at ${pluginJson.logo}`, fs.existsSync(logoPath));
const logoContent = fs.readFileSync(logoPath, "utf-8");
assert("logo.svg is valid square SVG (256x256)", logoContent.includes('viewBox="0 0 256 256"'));

// 3. Verify mcp_config.json
const mcpConfigPath = path.join(rootDir, "mcp_config.json");
assert("mcp_config.json exists", fs.existsSync(mcpConfigPath));
const mcpConfig = JSON.parse(fs.readFileSync(mcpConfigPath, "utf-8"));
assert("mcp_config.json defines namespaced 'systemores-cloud' server", Boolean(mcpConfig.mcpServers?.["systemores-cloud"]?.serverUrl));

// 4. Verify subagent, skill, and rules
const agentPath = path.join(rootDir, "agents/systemores-auditor.md");
const skillPath = path.join(rootDir, "skills/systemores-audit/SKILL.md");
const rulesPath = path.join(rootDir, "rules/AGENTS.md");
assert("agents/systemores-auditor.md exists", fs.existsSync(agentPath));
assert("skills/systemores-audit/SKILL.md exists", fs.existsSync(skillPath));
assert("rules/AGENTS.md exists", fs.existsSync(rulesPath));

const rulesContent = fs.readFileSync(rulesPath, "utf-8");
assert("rules/AGENTS.md has no YAML frontmatter", !rulesContent.trimStart().startsWith("---"));

// 5. Verify cross-IDE manifests
assert(".claude-plugin/plugin.json exists", fs.existsSync(path.join(rootDir, ".claude-plugin/plugin.json")));
assert(".claude-plugin/marketplace.json exists", fs.existsSync(path.join(rootDir, ".claude-plugin/marketplace.json")));
assert("gemini-extension.json exists", fs.existsSync(path.join(rootDir, "gemini-extension.json")));

console.log(`\n──────────────────────────────────────────`);
console.log(`Verification Summary: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
console.log("✅ Systemores Plugin bundle is valid and ready for distribution.");
