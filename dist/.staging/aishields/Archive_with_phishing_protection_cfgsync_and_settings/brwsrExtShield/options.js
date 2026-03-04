const DEFAULTS = {
  endpoint: "http://localhost:8000/telemetry/ingest",
  apiKey: "",
  tenantId: "demo",

  // General behavior
  telemetryEnabled: true,
  redactPIIEnabled: true,

  phishingProtectionEnabled: true,
  phishingMode: "redirect",
  phishingAllowlistDomains: [],
};

function load() {
  chrome.storage.sync.get(DEFAULTS, (cfg) => {
    document.getElementById("endpoint").value = cfg.endpoint;
    document.getElementById("apiKey").value = cfg.apiKey;
    document.getElementById("tenantId").value = cfg.tenantId;

    document.getElementById("telemetryEnabled").checked = cfg.telemetryEnabled !== false;
    document.getElementById("redactPIIEnabled").checked = cfg.redactPIIEnabled !== false;

    document.getElementById("phishingProtectionEnabled").checked = !!cfg.phishingProtectionEnabled;
    document.getElementById("phishingMode").value = cfg.phishingMode || "redirect";
    const allowlist = Array.isArray(cfg.phishingAllowlistDomains) ? cfg.phishingAllowlistDomains : [];
    document.getElementById("phishingAllowlistDomains").value = allowlist.join("\n");
  });
}

function save() {
  const endpoint = document.getElementById("endpoint").value.trim();
  const apiKey = document.getElementById("apiKey").value.trim();
  const tenantId = document.getElementById("tenantId").value.trim();

  const telemetryEnabled = document.getElementById("telemetryEnabled").checked;
  const redactPIIEnabled = document.getElementById("redactPIIEnabled").checked;

  const phishingProtectionEnabled = document.getElementById("phishingProtectionEnabled").checked;
  const phishingMode = document.getElementById("phishingMode").value;
  const phishingAllowlistDomains = document
    .getElementById("phishingAllowlistDomains")
    .value
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  chrome.storage.sync.set(
    {
      endpoint,
      apiKey,
      tenantId,
      telemetryEnabled,
      redactPIIEnabled,
      phishingProtectionEnabled,
      phishingMode,
      phishingAllowlistDomains,
    },
    () => {
    const status = document.getElementById("status");
    status.textContent = "Saved.";
    setTimeout(() => (status.textContent = ""), 1500);
    }
  );
}

document.getElementById("save").addEventListener("click", save);
document.addEventListener("DOMContentLoaded", load);
