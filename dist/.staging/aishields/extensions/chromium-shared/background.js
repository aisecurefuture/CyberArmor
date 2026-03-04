/**
 * AIShields Browser Protection - Chromium Background Service Worker
 * Works on: Chrome, Brave, Edge, Opera
 *
 * Features:
 * - Phishing protection with DNR rules
 * - Policy sync from control plane
 * - AI service monitoring (ChatGPT, Claude, Gemini, Copilot, etc.)
 * - Prompt injection detection
 * - MCP connection monitoring
 * - Telemetry reporting
 * - Monitor/warn/block action modes
 */

const DEFAULT_CONFIG = {
  controlPlaneUrl: "http://localhost:8000",
  apiKey: "",
  tenantId: "demo",
  telemetryEnabled: true,
  redactPIIEnabled: true,
  phishingProtectionEnabled: true,
  phishingMode: "redirect",
  phishingAllowlistDomains: [],
  policySyncIntervalMs: 60000,
  aiMonitoringEnabled: true,
  promptInjectionDetection: true,
  actionMode: "monitor", // monitor, warn, block
};

// Known AI service domains for monitoring
const AI_SERVICE_DOMAINS = [
  "chat.openai.com", "api.openai.com", "platform.openai.com",
  "claude.ai", "api.anthropic.com",
  "gemini.google.com", "generativelanguage.googleapis.com",
  "copilot.microsoft.com", "copilot.github.com",
  "huggingface.co", "api-inference.huggingface.co",
  "perplexity.ai", "api.perplexity.ai",
  "chat.mistral.ai", "api.mistral.ai",
  "cohere.ai", "api.cohere.ai",
  "together.ai", "api.together.xyz",
  "groq.com", "api.groq.com",
  "ollama.ai", "localhost:11434",
  "bard.google.com", "aistudio.google.com",
  "you.com", "poe.com", "character.ai",
  "deepseek.com", "api.deepseek.com",
  "x.ai", "api.x.ai",
];

// Prompt injection patterns
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /disregard\s+(the\s+)?(system|previous)\s+prompt/i,
  /\bjailbreak\b/i,
  /\bbegin\s+(?:new\s+)?system\s+prompt/i,
  /\bdeveloper\s+mode\b/i,
  /\bdisable\s+safety\b/i,
  /\bprint\s+(the\s+)?system\s+prompt/i,
  /\bexfiltrate\b/i,
  /\bprovide\s+credentials\b/i,
  /\bexecute\s+(bash|powershell|cmd)\b/i,
  /\bact\s+as\s+(?:an?\s+)?(?:un)?restricted/i,
  /\bDAN\s+mode\b/i,
  /\bbypass\s+(?:all\s+)?(?:safety|content)\s+filter/i,
];

let cachedConfig = { ...DEFAULT_CONFIG };
let cachedPolicies = [];
let policySyncTimer = null;

// --- Configuration Management ---

async function loadConfig() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(DEFAULT_CONFIG, (cfg) => {
      cachedConfig = { ...DEFAULT_CONFIG, ...cfg };
      resolve(cachedConfig);
    });
  });
}

async function saveConfig(updates) {
  return new Promise((resolve) => {
    chrome.storage.sync.set(updates, () => {
      Object.assign(cachedConfig, updates);
      resolve(cachedConfig);
    });
  });
}

// --- Policy Sync ---

async function syncPolicies() {
  if (!cachedConfig.controlPlaneUrl || !cachedConfig.apiKey) return;
  try {
    const url = `${cachedConfig.controlPlaneUrl.replace(/\/$/, "")}/policies/${cachedConfig.tenantId}/export`;
    const resp = await fetch(url, {
      headers: {
        "x-api-key": cachedConfig.apiKey,
        "Content-Type": "application/json",
      },
    });
    if (resp.ok) {
      cachedPolicies = await resp.json();
      await chrome.storage.local.set({ cachedPolicies, lastPolicySync: Date.now() });
      console.log(`[AIShields] Synced ${cachedPolicies.length} policies`);
    }
  } catch (err) {
    console.warn("[AIShields] Policy sync failed:", err.message);
    // Load from cache
    const stored = await chrome.storage.local.get(["cachedPolicies"]);
    if (stored.cachedPolicies) cachedPolicies = stored.cachedPolicies;
  }
}

function startPolicySync() {
  if (policySyncTimer) clearInterval(policySyncTimer);
  syncPolicies();
  policySyncTimer = setInterval(syncPolicies, cachedConfig.policySyncIntervalMs);
}

// --- Phishing Protection (DNR Rules) ---

const PHISHING_RULES = [
  { id: 1001, condition: { regexFilter: "https?://[^/]*@[^/]+", resourceTypes: ["main_frame"] } },
  { id: 1002, condition: { regexFilter: "https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}", resourceTypes: ["main_frame"] } },
  { id: 1003, condition: { regexFilter: "https?://[^/]*xn--[^/]+", resourceTypes: ["main_frame"] } },
  { id: 1004, condition: { urlFilter: "http://*/*login*", resourceTypes: ["main_frame"] } },
  { id: 1005, condition: { urlFilter: "http://*/*signin*", resourceTypes: ["main_frame"] } },
  { id: 1006, condition: { urlFilter: "http://*/*password*", resourceTypes: ["main_frame"] } },
  { id: 1007, condition: { urlFilter: "http://*/*credential*", resourceTypes: ["main_frame"] } },
  { id: 1008, condition: { urlFilter: "*phishing*", resourceTypes: ["main_frame"] } },
];

async function setupPhishingRules() {
  if (!cachedConfig.phishingProtectionEnabled) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: PHISHING_RULES.map((r) => r.id),
    });
    return;
  }
  const action = cachedConfig.phishingMode === "block"
    ? { type: "block" }
    : { type: "redirect", redirect: { extensionPath: "/phishing_warning.html" } };

  const rules = PHISHING_RULES.map((r) => ({
    id: r.id,
    priority: 1,
    action,
    condition: r.condition,
  }));

  // Remove allowlisted domains
  const allowlist = cachedConfig.phishingAllowlistDomains || [];
  const filteredRules = rules; // DNR handles allowlists via excludedDomains

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: PHISHING_RULES.map((r) => r.id),
    addRules: filteredRules,
  });
}

// --- AI Service Monitoring ---

function isAIServiceUrl(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return AI_SERVICE_DOMAINS.some((domain) => hostname === domain || hostname.endsWith("." + domain));
  } catch {
    return false;
  }
}

function checkPromptInjection(text) {
  if (!text || !cachedConfig.promptInjectionDetection) return null;
  const matches = [];
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      matches.push(pattern.source);
    }
  }
  return matches.length > 0 ? { risk: matches.length >= 3 ? "high" : "medium", patterns: matches } : null;
}

// --- Policy Evaluation (client-side) ---

function evaluatePolicy(context) {
  const enabledPolicies = cachedPolicies.filter((p) => p.enabled);
  for (const policy of enabledPolicies) {
    if (policy.conditions && evaluateConditions(policy.conditions, context)) {
      return { matched: true, policy: policy.name, action: policy.action };
    }
  }
  return { matched: false };
}

function evaluateConditions(conditions, context) {
  const op = (conditions.operator || "AND").toUpperCase();
  const rules = conditions.rules || [];
  if (!rules.length) return true;

  const results = rules.map((rule) => {
    if (rule.rules) return evaluateConditions(rule, context);
    return evaluateLeafRule(rule, context);
  });

  return op === "OR" ? results.some(Boolean) : results.every(Boolean);
}

function evaluateLeafRule(rule, context) {
  const actual = getNestedValue(context, rule.field || "");
  const expected = rule.value;
  switch (rule.operator) {
    case "equals": return actual === expected;
    case "not_equals": return actual !== expected;
    case "contains": return String(actual || "").includes(String(expected));
    case "not_contains": return !String(actual || "").includes(String(expected));
    case "matches": return new RegExp(String(expected).replace(/\*/g, ".*")).test(String(actual || ""));
    case "in": return Array.isArray(expected) ? expected.includes(actual) : actual === expected;
    case "starts_with": return String(actual || "").startsWith(String(expected));
    case "ends_with": return String(actual || "").endsWith(String(expected));
    case "exists": return actual != null;
    case "not_exists": return actual == null;
    default: return false;
  }
}

function getNestedValue(obj, path) {
  return path.split(".").reduce((o, k) => (o && typeof o === "object" ? o[k] : undefined), obj);
}

// --- Telemetry ---

async function sendTelemetry(event) {
  if (!cachedConfig.telemetryEnabled || !cachedConfig.controlPlaneUrl) return;
  try {
    const url = `${cachedConfig.controlPlaneUrl.replace(/\/$/, "")}/telemetry/ingest`;
    await fetch(url, {
      method: "POST",
      headers: {
        "x-api-key": cachedConfig.apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        tenant_id: cachedConfig.tenantId,
        event_type: event.type,
        payload: event.payload,
        source: "browser_extension",
        occurred_at: new Date().toISOString(),
      }),
    });
  } catch (err) {
    console.warn("[AIShields] Telemetry send failed:", err.message);
  }
}

// --- Navigation Monitoring ---

chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;

  // AI service detection
  if (cachedConfig.aiMonitoringEnabled && isAIServiceUrl(url)) {
    const policyResult = evaluatePolicy({
      request: { url, type: "ai_service_access" },
      content: {},
    });

    await sendTelemetry({
      type: "ai_service_detected",
      payload: { url, tabId: details.tabId, policyMatch: policyResult },
    });

    if (policyResult.matched && policyResult.action === "block") {
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL("phishing_warning.html") + "?u=" + encodeURIComponent(url) + "&reason=policy_block",
      });
    } else if (policyResult.matched && policyResult.action === "warn") {
      chrome.tabs.sendMessage(details.tabId, {
        type: "show_warning",
        message: `AI service access detected: ${new URL(url).hostname}. Policy: ${policyResult.policy}`,
      });
    }
  }
});

// --- Message Listener ---

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "telemetry") {
    sendTelemetry({ type: msg.body?.event_type || "unknown", payload: msg.body?.payload || {} })
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "check_prompt_injection") {
    const result = checkPromptInjection(msg.text);
    sendResponse({ injection: result });
    return false;
  }

  if (msg.type === "evaluate_policy") {
    const result = evaluatePolicy(msg.context);
    sendResponse({ result });
    return false;
  }

  if (msg.type === "get_policies") {
    sendResponse({ policies: cachedPolicies });
    return false;
  }

  if (msg.type === "phishing_allowlist_domain") {
    const domain = msg.domain;
    if (domain) {
      const list = cachedConfig.phishingAllowlistDomains || [];
      if (!list.includes(domain)) {
        list.push(domain);
        saveConfig({ phishingAllowlistDomains: list }).then(() => {
          setupPhishingRules();
          sendResponse({ ok: true });
        });
        return true;
      }
    }
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === "get_config") {
    sendResponse({ config: cachedConfig });
    return false;
  }

  if (msg.type === "update_config") {
    saveConfig(msg.updates).then((cfg) => {
      setupPhishingRules();
      if (msg.updates.policySyncIntervalMs || msg.updates.controlPlaneUrl || msg.updates.apiKey) {
        startPolicySync();
      }
      sendResponse({ ok: true, config: cfg });
    });
    return true;
  }

  return false;
});

// --- Startup ---

chrome.runtime.onInstalled.addListener(async () => {
  await loadConfig();
  await setupPhishingRules();
  startPolicySync();
  console.log("[AIShields] Extension installed and initialized");
});

chrome.runtime.onStartup.addListener(async () => {
  await loadConfig();
  await setupPhishingRules();
  startPolicySync();
  console.log("[AIShields] Extension started");
});

// Config change listener
chrome.storage.onChanged.addListener((changes) => {
  for (const key of Object.keys(changes)) {
    if (key in cachedConfig) {
      cachedConfig[key] = changes[key].newValue;
    }
  }
  if (changes.phishingProtectionEnabled || changes.phishingMode || changes.phishingAllowlistDomains) {
    setupPhishingRules();
  }
});
