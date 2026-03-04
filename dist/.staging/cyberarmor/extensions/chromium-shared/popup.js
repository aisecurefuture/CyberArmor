/**
 * AIShields Protect - Popup Logic
 * Communicates with background service worker for state management.
 */

(function () {
  "use strict";

  const STORAGE_KEY_ALERTS = "aishields_alerts";
  const STORAGE_KEY_STATS = "aishields_stats";
  const MAX_ALERTS = 50;

  // --- DOM References ---

  const els = {
    connectionStatus: document.getElementById("connection-status"),
    protectionBadge: document.getElementById("protection-badge"),
    togglePII: document.getElementById("toggle-pii"),
    togglePhishing: document.getElementById("toggle-phishing"),
    toggleAI: document.getElementById("toggle-ai"),
    toggleInjection: document.getElementById("toggle-injection"),
    modeSelector: document.getElementById("mode-selector"),
    statThreats: document.getElementById("stat-threats"),
    statPII: document.getElementById("stat-pii"),
    statAI: document.getElementById("stat-ai"),
    alertList: document.getElementById("alert-list"),
    btnClearAlerts: document.getElementById("btn-clear-alerts"),
    policyCount: document.getElementById("policy-count"),
    policySyncTime: document.getElementById("policy-sync-time"),
    btnSyncPolicies: document.getElementById("btn-sync-policies"),
    btnOptions: document.getElementById("btn-options"),
    btnDashboard: document.getElementById("btn-dashboard"),
  };

  // --- Initialization ---

  async function init() {
    await loadConfig();
    await loadStats();
    await loadAlerts();
    await checkConnection();
    setupEventListeners();
  }

  async function loadConfig() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: "get_config" }, (response) => {
        if (chrome.runtime.lastError || !response) {
          resolve();
          return;
        }
        const cfg = response.config || {};
        els.togglePII.checked = cfg.redactPIIEnabled !== false;
        els.togglePhishing.checked = cfg.phishingProtectionEnabled !== false;
        els.toggleAI.checked = cfg.aiMonitoringEnabled !== false;
        els.toggleInjection.checked = cfg.promptInjectionDetection !== false;

        // Set active mode
        const mode = cfg.actionMode || "monitor";
        document.querySelectorAll(".mode-option").forEach((btn) => {
          btn.classList.toggle("active", btn.dataset.mode === mode);
        });

        updateProtectionBadge(cfg);
        resolve();
      });
    });
  }

  async function loadStats() {
    return new Promise((resolve) => {
      chrome.storage.local.get([STORAGE_KEY_STATS], (data) => {
        const stats = data[STORAGE_KEY_STATS] || { threats: 0, pii: 0, ai: 0 };
        els.statThreats.textContent = formatNumber(stats.threats);
        els.statPII.textContent = formatNumber(stats.pii);
        els.statAI.textContent = formatNumber(stats.ai);
        resolve();
      });
    });
  }

  async function loadAlerts() {
    return new Promise((resolve) => {
      chrome.storage.local.get([STORAGE_KEY_ALERTS], (data) => {
        const alerts = data[STORAGE_KEY_ALERTS] || [];
        renderAlerts(alerts);
        resolve();
      });
    });
  }

  async function checkConnection() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: "get_config" }, (response) => {
        if (chrome.runtime.lastError || !response) {
          setConnectionStatus("disconnected", "No response");
          resolve();
          return;
        }
        const cfg = response.config || {};
        if (!cfg.controlPlaneUrl || !cfg.apiKey) {
          setConnectionStatus("disconnected", "Not configured");
        } else {
          // Try a quick ping to the control plane
          fetch(`${cfg.controlPlaneUrl.replace(/\/$/, "")}/health`, {
            method: "GET",
            headers: { "x-api-key": cfg.apiKey },
            signal: AbortSignal.timeout(5000),
          })
            .then((resp) => {
              if (resp.ok) {
                setConnectionStatus("connected", "Connected");
              } else {
                setConnectionStatus("error", `HTTP ${resp.status}`);
              }
            })
            .catch(() => {
              setConnectionStatus("disconnected", "Offline");
            });
        }
        resolve();
      });
    });
  }

  // --- Event Listeners ---

  function setupEventListeners() {
    // Toggle listeners
    els.togglePII.addEventListener("change", () => {
      updateConfig({ redactPIIEnabled: els.togglePII.checked });
    });
    els.togglePhishing.addEventListener("change", () => {
      updateConfig({ phishingProtectionEnabled: els.togglePhishing.checked });
    });
    els.toggleAI.addEventListener("change", () => {
      updateConfig({ aiMonitoringEnabled: els.toggleAI.checked });
    });
    els.toggleInjection.addEventListener("change", () => {
      updateConfig({ promptInjectionDetection: els.toggleInjection.checked });
    });

    // Mode selector
    els.modeSelector.addEventListener("click", (e) => {
      const btn = e.target.closest(".mode-option");
      if (!btn) return;
      document.querySelectorAll(".mode-option").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      updateConfig({ actionMode: btn.dataset.mode });
    });

    // Clear alerts
    els.btnClearAlerts.addEventListener("click", () => {
      chrome.storage.local.set({ [STORAGE_KEY_ALERTS]: [] }, () => {
        renderAlerts([]);
      });
    });

    // Sync policies
    els.btnSyncPolicies.addEventListener("click", () => {
      els.btnSyncPolicies.disabled = true;
      els.btnSyncPolicies.textContent = "Syncing...";
      chrome.runtime.sendMessage({ type: "get_policies" }, (response) => {
        const count = response?.policies?.length || 0;
        els.policyCount.textContent = `${count} policies loaded`;
        els.policySyncTime.textContent = "Just now";
        els.btnSyncPolicies.disabled = false;
        els.btnSyncPolicies.textContent = "Sync Now";
      });
    });

    // Load policy info
    chrome.runtime.sendMessage({ type: "get_policies" }, (response) => {
      if (response?.policies) {
        els.policyCount.textContent = `${response.policies.length} policies loaded`;
      }
    });
    chrome.storage.local.get(["lastPolicySync"], (data) => {
      if (data.lastPolicySync) {
        els.policySyncTime.textContent = timeAgo(data.lastPolicySync);
      }
    });

    // Navigation buttons
    els.btnOptions.addEventListener("click", () => {
      chrome.runtime.openOptionsPage();
    });
    els.btnDashboard.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "get_config" }, (response) => {
        const url = response?.config?.controlPlaneUrl || "http://localhost:8000";
        chrome.tabs.create({ url: `${url.replace(/\/$/, "")}/dashboard` });
      });
    });
  }

  // --- Config Update ---

  function updateConfig(updates) {
    chrome.runtime.sendMessage({ type: "update_config", updates }, (response) => {
      if (response?.config) {
        updateProtectionBadge(response.config);
      }
    });
  }

  // --- UI Helpers ---

  function setConnectionStatus(state, label) {
    els.connectionStatus.className = `connection-indicator ${state}`;
    els.connectionStatus.querySelector(".label").textContent = label;
  }

  function updateProtectionBadge(cfg) {
    const allEnabled =
      cfg.redactPIIEnabled !== false &&
      cfg.phishingProtectionEnabled !== false &&
      cfg.aiMonitoringEnabled !== false;

    const noneEnabled =
      cfg.redactPIIEnabled === false &&
      cfg.phishingProtectionEnabled === false &&
      cfg.aiMonitoringEnabled === false;

    if (noneEnabled) {
      els.protectionBadge.className = "status-badge status-badge--inactive";
      els.protectionBadge.innerHTML = '<span class="status-dot status-dot--inactive"></span>Disabled';
    } else if (allEnabled) {
      els.protectionBadge.className = "status-badge status-badge--active";
      els.protectionBadge.innerHTML = '<span class="status-dot status-dot--active status-dot--pulse"></span>Active';
    } else {
      els.protectionBadge.className = "status-badge status-badge--warning";
      els.protectionBadge.innerHTML = '<span class="status-dot status-dot--warning"></span>Partial';
    }
  }

  function renderAlerts(alerts) {
    if (!alerts || alerts.length === 0) {
      els.alertList.innerHTML = `
        <li class="empty-state">
          <div class="empty-state-icon">&#x2714;</div>
          <div>No recent alerts</div>
        </li>
      `;
      return;
    }

    const sorted = alerts.slice().sort((a, b) => b.timestamp - a.timestamp).slice(0, 10);
    els.alertList.innerHTML = sorted
      .map((alert) => {
        const severity = alert.severity || "medium";
        const iconMap = { critical: "!", high: "!", medium: "i", low: "-" };
        return `
          <li class="alert-item slide-in">
            <span class="alert-icon alert-icon--${severity}">${iconMap[severity] || "i"}</span>
            <div class="alert-text">
              <div class="alert-title">${escapeHtml(alert.title || alert.type || "Alert")}</div>
              <div class="alert-meta">${escapeHtml(alert.domain || "")} &middot; ${timeAgo(alert.timestamp)}</div>
            </div>
            <span class="severity-badge severity-${severity}">${severity}</span>
          </li>
        `;
      })
      .join("");
  }

  function formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
    if (n >= 1000) return (n / 1000).toFixed(1) + "K";
    return String(n);
  }

  function timeAgo(timestamp) {
    if (!timestamp) return "Unknown";
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    if (seconds < 60) return "Just now";
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str || "";
    return div.innerHTML;
  }

  // --- Start ---
  document.addEventListener("DOMContentLoaded", init);
})();
