console.log("[AiShields] background service worker started");

// This extension uses a small set of high-confidence heuristics to protect users from
// accidental clicks on common phishing URL patterns.
//
// Important: this is NOT a full URL reputation system; it's designed to be low false-positive.
// Rules are applied via MV3 Declarative Net Request (DNR), so we can block/redirect before load.

const DEFAULT_CONFIG = {
  endpoint: "http://localhost:8000/telemetry/ingest",
  apiKey: "change-me",
  tenantId: "demo",

  // General behavior
  telemetryEnabled: true,
  redactPIIEnabled: true,

  // Phishing protection
  phishingProtectionEnabled: true,
  phishingMode: "redirect", // "redirect" (default) or "block"
  phishingAllowlistDomains: [], // array of domains (e.g., "example.com")
};

// Keep rule ids stable (do NOT change once published) so updates are deterministic.
const PHISHING_RULE_IDS = {
  USERINFO_AT: 910001,
  IP_HOST: 910002,
  PUNYCODE: 910003,
  HTTP_LOGIN_KEYWORDS: 910004,
};

function storageGet(defaults) {
  return new Promise((resolve) => chrome.storage.sync.get(defaults, (res) => resolve(res)));
}

async function getConfig() {
  return storageGet(DEFAULT_CONFIG);
}

function normalizeDomainList(domains) {
  if (!Array.isArray(domains)) return [];
  return domains
    .map((d) => String(d || "").trim().toLowerCase())
    .filter(Boolean)
    // strip leading wildcards/protocols
    .map((d) => d.replace(/^\*\.?/, ""))
    .map((d) => d.replace(/^https?:\/\//, ""))
    .map((d) => d.replace(/\/$/, ""));
}

function buildPhishingRules({ mode, allowlistDomains }) {
  const action = mode === "block"
    ? { type: "block" }
    : {
        type: "redirect",
        redirect: {
          // We redirect to an extension warning page (keeps the original URL in a querystring).
          // The warning page can offer "Continue" (temporarily allowlist the domain).
          regexSubstitution: `${chrome.runtime.getURL("phishing_warning.html")}?u=\\0`,
        },
      };

  const excludedDomains = normalizeDomainList(allowlistDomains);

  // DNR uses RE2 regex. Keep patterns simple.
  return [
    {
      id: PHISHING_RULE_IDS.USERINFO_AT,
      priority: 1,
      action,
      condition: {
        resourceTypes: ["main_frame"],
        regexFilter: "^https?://[^/]*@",
        excludedDomains,
      },
    },
    {
      id: PHISHING_RULE_IDS.IP_HOST,
      priority: 1,
      action,
      condition: {
        resourceTypes: ["main_frame"],
        // http(s)://<IPv4>(:port)?/...
        regexFilter: "^https?://(\\d{1,3}\\.){3}\\d{1,3}(:\\d+)?(/|$)",
        excludedDomains,
      },
    },
    {
      id: PHISHING_RULE_IDS.PUNYCODE,
      priority: 1,
      action,
      condition: {
        resourceTypes: ["main_frame"],
        // Punycode domains often used for look-alike attacks.
        // (We only match if the hostname begins with xn--)
        regexFilter: "^https?://xn--",
        excludedDomains,
      },
    },
    {
      id: PHISHING_RULE_IDS.HTTP_LOGIN_KEYWORDS,
      priority: 1,
      action,
      condition: {
        resourceTypes: ["main_frame"],
        // Login/verify/update flows over *plain HTTP* are very commonly phishing.
        regexFilter: "^http://.*(login|signin|verify|update|secure|account)",
        excludedDomains,
      },
    },
  ];
}

async function applyPhishingProtection() {
  const cfg = await getConfig();
  const enabled = !!cfg.phishingProtectionEnabled;

  const removeRuleIds = Object.values(PHISHING_RULE_IDS);
  if (!enabled) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules: [],
    });
    console.log("[AiShields] phishing protection disabled");
    return;
  }

  const rules = buildPhishingRules({
    mode: cfg.phishingMode || "redirect",
    allowlistDomains: cfg.phishingAllowlistDomains || [],
  });

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules: rules,
  });

  console.log("[AiShields] phishing protection enabled:", {
    mode: cfg.phishingMode,
    allowlistCount: (cfg.phishingAllowlistDomains || []).length,
  });
}

chrome.runtime.onInstalled.addListener(async () => {
  // Ensure defaults exist for new installs.
  await storageGet(DEFAULT_CONFIG);
  await applyPhishingProtection();
});

chrome.runtime.onStartup.addListener(async () => {
  await applyPhishingProtection();
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "sync") return;
  const phishingKeys = ["phishingProtectionEnabled", "phishingMode", "phishingAllowlistDomains"];
  if (phishingKeys.some((k) => k in changes)) {
    applyPhishingProtection().catch((e) => console.warn("[AiShields] phishing rules update failed", e));
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "content_loaded") {
    console.log("[AiShields] content loaded on", message.url || sender.tab?.url);
  }

  if (message?.type === "telemetry") {
    getConfig().then((cfg) => {
      // Allow deployments to disable outbound telemetry entirely.
      if (cfg.telemetryEnabled === false) {
        sendResponse({ ok: true, skipped: true });
        return;
      }
      const body = {
        ...message.body,
        tenant_id: cfg.tenantId || DEFAULT_CONFIG.tenantId,
      };
      fetch(cfg.endpoint || DEFAULT_CONFIG.endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": cfg.apiKey || DEFAULT_CONFIG.apiKey,
        },
        body: JSON.stringify(body),
      })
        .then(() => sendResponse({ ok: true }))
        .catch((err) => {
          console.warn("[AiShields] telemetry failed", err);
          sendResponse({ ok: false, error: String(err) });
        });
    });
    return true;
  }

  if (message?.type === "phishing_allowlist_domain") {
    // Called from phishing_warning.js when the user clicks "Continue".
    getConfig().then(async (cfg) => {
      const domain = String(message.domain || "").trim().toLowerCase();
      if (!domain) {
        sendResponse({ ok: false, error: "missing domain" });
        return;
      }

      const current = normalizeDomainList(cfg.phishingAllowlistDomains || []);
      if (!current.includes(domain)) {
        current.push(domain);
        chrome.storage.sync.set({ phishingAllowlistDomains: current }, () => {
          sendResponse({ ok: true });
        });
      } else {
        sendResponse({ ok: true });
      }
    });
    return true;
  }
});
