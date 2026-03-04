/**
 * AIShields Protect - Options Page Logic
 * Manages extension settings via chrome.storage.sync with real-time updates.
 */

(function () {
  "use strict";

  // AI services list for the monitoring config
  const AI_SERVICES = [
    { id: "chatgpt", name: "ChatGPT (OpenAI)", domains: ["chat.openai.com", "chatgpt.com"] },
    { id: "claude", name: "Claude (Anthropic)", domains: ["claude.ai"] },
    { id: "gemini", name: "Gemini (Google)", domains: ["gemini.google.com"] },
    { id: "copilot", name: "Copilot (Microsoft)", domains: ["copilot.microsoft.com"] },
    { id: "perplexity", name: "Perplexity AI", domains: ["perplexity.ai"] },
    { id: "huggingface", name: "HuggingFace Chat", domains: ["huggingface.co"] },
    { id: "mistral", name: "Mistral AI", domains: ["chat.mistral.ai"] },
    { id: "poe", name: "Poe", domains: ["poe.com"] },
    { id: "you", name: "You.com", domains: ["you.com"] },
    { id: "deepseek", name: "DeepSeek", domains: ["deepseek.com"] },
    { id: "cohere", name: "Cohere", domains: ["coral.cohere.com"] },
    { id: "meta_ai", name: "Meta AI", domains: ["meta.ai"] },
    { id: "xai", name: "xAI (Grok)", domains: ["x.ai"] },
  ];

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
    aiFileUploadMonitoring: true,
    logAIPrompts: false,
    actionMode: "monitor",
    xssDetectionEnabled: true,
    cmdInjectionEnabled: true,
    autoRedactPII: true,
    dlpSensitivity: "medium",
    customPatterns: [],
    disabledAIServices: [],
  };

  let currentConfig = { ...DEFAULT_CONFIG };

  // --- DOM References ---

  const els = {
    // Connection
    controlPlaneUrl: document.getElementById("control-plane-url"),
    apiKey: document.getElementById("api-key"),
    tenantId: document.getElementById("tenant-id"),
    btnTestConnection: document.getElementById("btn-test-connection"),
    connectionTestResult: document.getElementById("connection-test-result"),
    policySyncInterval: document.getElementById("policy-sync-interval"),
    btnForceSync: document.getElementById("btn-force-sync"),
    lastSyncInfo: document.getElementById("last-sync-info"),

    // Protection
    actionMode: document.getElementById("action-mode"),
    optPhishingEnabled: document.getElementById("opt-phishing-enabled"),
    phishingMode: document.getElementById("phishing-mode"),
    phishingAllowlist: document.getElementById("phishing-allowlist"),
    optXssEnabled: document.getElementById("opt-xss-enabled"),
    optCmdInjectionEnabled: document.getElementById("opt-cmd-injection-enabled"),

    // AI Monitoring
    optAIMonitoring: document.getElementById("opt-ai-monitoring"),
    optPromptInjection: document.getElementById("opt-prompt-injection"),
    optAIFileUpload: document.getElementById("opt-ai-file-upload"),
    optLogPrompts: document.getElementById("opt-log-prompts"),
    aiServiceList: document.getElementById("ai-service-list"),

    // DLP
    optPIIEnabled: document.getElementById("opt-pii-enabled"),
    optAutoRedact: document.getElementById("opt-auto-redact"),
    dlpSensitivity: document.getElementById("dlp-sensitivity"),
    customPatterns: document.getElementById("custom-patterns"),

    // Advanced
    optTelemetry: document.getElementById("opt-telemetry"),
    btnExportConfig: document.getElementById("btn-export-config"),
    btnImportConfig: document.getElementById("btn-import-config"),
    importFileInput: document.getElementById("import-file-input"),
    btnResetConfig: document.getElementById("btn-reset-config"),
    debugVersion: document.getElementById("debug-version"),
    debugPolicyCount: document.getElementById("debug-policy-count"),
    debugLastSync: document.getElementById("debug-last-sync"),
    debugStorage: document.getElementById("debug-storage"),

    // Global
    btnSave: document.getElementById("btn-save"),
    saveStatus: document.getElementById("save-status"),
    toast: document.getElementById("toast"),
  };

  // --- Initialization ---

  async function init() {
    await loadConfig();
    populateUI();
    renderAIServiceList();
    setupEventListeners();
    loadDebugInfo();
  }

  async function loadConfig() {
    return new Promise((resolve) => {
      chrome.storage.sync.get(DEFAULT_CONFIG, (cfg) => {
        currentConfig = { ...DEFAULT_CONFIG, ...cfg };
        resolve();
      });
    });
  }

  function populateUI() {
    els.controlPlaneUrl.value = currentConfig.controlPlaneUrl;
    els.apiKey.value = currentConfig.apiKey;
    els.tenantId.value = currentConfig.tenantId;
    els.policySyncInterval.value = Math.round(currentConfig.policySyncIntervalMs / 1000);
    els.actionMode.value = currentConfig.actionMode;
    els.optPhishingEnabled.checked = currentConfig.phishingProtectionEnabled;
    els.phishingMode.value = currentConfig.phishingMode;
    els.phishingAllowlist.value = (currentConfig.phishingAllowlistDomains || []).join("\n");
    els.optXssEnabled.checked = currentConfig.xssDetectionEnabled !== false;
    els.optCmdInjectionEnabled.checked = currentConfig.cmdInjectionEnabled !== false;
    els.optAIMonitoring.checked = currentConfig.aiMonitoringEnabled;
    els.optPromptInjection.checked = currentConfig.promptInjectionDetection;
    els.optAIFileUpload.checked = currentConfig.aiFileUploadMonitoring !== false;
    els.optLogPrompts.checked = currentConfig.logAIPrompts === true;
    els.optPIIEnabled.checked = currentConfig.redactPIIEnabled;
    els.optAutoRedact.checked = currentConfig.autoRedactPII !== false;
    els.dlpSensitivity.value = currentConfig.dlpSensitivity || "medium";
    els.optTelemetry.checked = currentConfig.telemetryEnabled;

    // Custom patterns
    if (Array.isArray(currentConfig.customPatterns) && currentConfig.customPatterns.length > 0) {
      els.customPatterns.value = currentConfig.customPatterns.map((p) => `${p.label}|${p.pattern}`).join("\n");
    }
  }

  function renderAIServiceList() {
    const disabled = currentConfig.disabledAIServices || [];
    els.aiServiceList.innerHTML = AI_SERVICES.map((svc) => {
      const checked = !disabled.includes(svc.id);
      return `
        <div class="toggle-row">
          <div>
            <div class="toggle-label">${escapeHtml(svc.name)}</div>
            <div class="toggle-desc">${escapeHtml(svc.domains.join(", "))}</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" data-service-id="${svc.id}" ${checked ? "checked" : ""}>
            <span class="toggle-slider"></span>
          </label>
        </div>
      `;
    }).join("");
  }

  // --- Event Listeners ---

  function setupEventListeners() {
    // Tab navigation
    document.querySelectorAll(".options-nav-item").forEach((tab) => {
      tab.addEventListener("click", () => {
        document.querySelectorAll(".options-nav-item").forEach((t) => t.classList.remove("active"));
        document.querySelectorAll(".options-section").forEach((s) => s.classList.remove("active"));
        tab.classList.add("active");
        const target = document.getElementById(`tab-${tab.dataset.tab}`);
        if (target) target.classList.add("active");
      });
    });

    // Test connection
    els.btnTestConnection.addEventListener("click", testConnection);

    // Force sync
    els.btnForceSync.addEventListener("click", () => {
      els.btnForceSync.disabled = true;
      els.btnForceSync.textContent = "Syncing...";
      // Trigger a policy sync by sending a message to the background
      chrome.runtime.sendMessage({ type: "get_policies" }, (response) => {
        const count = response?.policies?.length || 0;
        els.lastSyncInfo.textContent = `Last sync: Just now (${count} policies)`;
        els.btnForceSync.disabled = false;
        els.btnForceSync.textContent = "Force Sync";
        showToast(`Synced ${count} policies`, "success");
      });
    });

    // Save
    els.btnSave.addEventListener("click", saveAll);

    // Export config
    els.btnExportConfig.addEventListener("click", exportConfig);

    // Import config
    els.btnImportConfig.addEventListener("click", () => els.importFileInput.click());
    els.importFileInput.addEventListener("change", importConfig);

    // Reset
    els.btnResetConfig.addEventListener("click", () => {
      if (confirm("Are you sure you want to reset all settings to their default values? This cannot be undone.")) {
        chrome.storage.sync.clear(() => {
          currentConfig = { ...DEFAULT_CONFIG };
          populateUI();
          renderAIServiceList();
          showToast("Settings reset to defaults", "success");
        });
      }
    });
  }

  // --- Save ---

  function collectFormValues() {
    // Parse custom patterns
    const patternsText = els.customPatterns.value.trim();
    const customPatterns = patternsText
      ? patternsText.split("\n").map((line) => {
          const [label, pattern] = line.split("|");
          return label && pattern ? { label: label.trim(), pattern: pattern.trim() } : null;
        }).filter(Boolean)
      : [];

    // Parse allowlist
    const allowlistText = els.phishingAllowlist.value.trim();
    const phishingAllowlistDomains = allowlistText
      ? allowlistText.split("\n").map((d) => d.trim()).filter(Boolean)
      : [];

    // Collect disabled AI services
    const disabledAIServices = [];
    els.aiServiceList.querySelectorAll("input[data-service-id]").forEach((cb) => {
      if (!cb.checked) {
        disabledAIServices.push(cb.dataset.serviceId);
      }
    });

    return {
      controlPlaneUrl: els.controlPlaneUrl.value.trim(),
      apiKey: els.apiKey.value,
      tenantId: els.tenantId.value.trim(),
      policySyncIntervalMs: parseInt(els.policySyncInterval.value, 10) * 1000 || 60000,
      actionMode: els.actionMode.value,
      phishingProtectionEnabled: els.optPhishingEnabled.checked,
      phishingMode: els.phishingMode.value,
      phishingAllowlistDomains,
      xssDetectionEnabled: els.optXssEnabled.checked,
      cmdInjectionEnabled: els.optCmdInjectionEnabled.checked,
      aiMonitoringEnabled: els.optAIMonitoring.checked,
      promptInjectionDetection: els.optPromptInjection.checked,
      aiFileUploadMonitoring: els.optAIFileUpload.checked,
      logAIPrompts: els.optLogPrompts.checked,
      redactPIIEnabled: els.optPIIEnabled.checked,
      autoRedactPII: els.optAutoRedact.checked,
      dlpSensitivity: els.dlpSensitivity.value,
      customPatterns,
      telemetryEnabled: els.optTelemetry.checked,
      disabledAIServices,
    };
  }

  function saveAll() {
    const values = collectFormValues();
    els.btnSave.disabled = true;
    els.btnSave.textContent = "Saving...";

    chrome.runtime.sendMessage({ type: "update_config", updates: values }, (response) => {
      els.btnSave.disabled = false;
      els.btnSave.textContent = "Save Settings";

      if (response?.ok) {
        currentConfig = { ...currentConfig, ...values };
        els.saveStatus.textContent = "Settings saved";
        showToast("Settings saved successfully", "success");
      } else {
        els.saveStatus.textContent = "Save failed";
        showToast("Failed to save settings", "danger");
      }
    });
  }

  // --- Connection Test ---

  async function testConnection() {
    const url = els.controlPlaneUrl.value.trim();
    const apiKey = els.apiKey.value;

    if (!url) {
      els.connectionTestResult.textContent = "Enter a URL first";
      els.connectionTestResult.className = "text-danger";
      return;
    }

    els.btnTestConnection.disabled = true;
    els.btnTestConnection.textContent = "Testing...";
    els.connectionTestResult.textContent = "";

    try {
      const resp = await fetch(`${url.replace(/\/$/, "")}/health`, {
        method: "GET",
        headers: apiKey ? { "x-api-key": apiKey } : {},
        signal: AbortSignal.timeout(10000),
      });

      if (resp.ok) {
        els.connectionTestResult.textContent = "Connected successfully";
        els.connectionTestResult.className = "text-success";
      } else {
        els.connectionTestResult.textContent = `HTTP ${resp.status}: ${resp.statusText}`;
        els.connectionTestResult.className = "text-danger";
      }
    } catch (err) {
      els.connectionTestResult.textContent = `Connection failed: ${err.message}`;
      els.connectionTestResult.className = "text-danger";
    }

    els.btnTestConnection.disabled = false;
    els.btnTestConnection.textContent = "Test Connection";
  }

  // --- Export / Import ---

  function exportConfig() {
    const data = JSON.stringify(currentConfig, null, 2);
    const blob = new Blob([data], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aishields-config-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("Configuration exported", "success");
  }

  function importConfig(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const imported = JSON.parse(e.target.result);
        // Validate it has expected keys
        if (typeof imported !== "object" || imported === null) {
          throw new Error("Invalid configuration format");
        }
        // Merge with defaults
        currentConfig = { ...DEFAULT_CONFIG, ...imported };
        populateUI();
        renderAIServiceList();
        showToast("Configuration imported. Click Save to apply.", "success");
      } catch (err) {
        showToast(`Import failed: ${err.message}`, "danger");
      }
    };
    reader.readAsText(file);
    // Reset input so same file can be re-imported
    event.target.value = "";
  }

  // --- Debug Info ---

  function loadDebugInfo() {
    const manifest = chrome.runtime.getManifest();
    els.debugVersion.textContent = manifest.version;

    chrome.storage.local.get(["cachedPolicies", "lastPolicySync"], (data) => {
      els.debugPolicyCount.textContent = (data.cachedPolicies || []).length;
      if (data.lastPolicySync) {
        els.debugLastSync.textContent = new Date(data.lastPolicySync).toLocaleString();
        els.lastSyncInfo.textContent = `Last sync: ${new Date(data.lastPolicySync).toLocaleString()}`;
      }
    });

    // Estimate storage usage
    chrome.storage.sync.getBytesInUse(null, (bytes) => {
      els.debugStorage.textContent = `${(bytes / 1024).toFixed(1)} KB of ${chrome.storage.sync.QUOTA_BYTES / 1024} KB (sync)`;
    });
  }

  // --- Utilities ---

  function showToast(message, type) {
    els.toast.textContent = message;
    els.toast.className = `toast toast--${type || "success"} visible`;
    setTimeout(() => {
      els.toast.classList.remove("visible");
    }, 3000);
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str || "";
    return div.innerHTML;
  }

  // --- Start ---
  document.addEventListener("DOMContentLoaded", init);
})();
