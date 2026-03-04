const DEFAULTS = {
  endpoint: "http://localhost:8000/telemetry/ingest",
  apiKey: "",
  tenantId: "demo",
};

function setStatus(ok, message) {
  const pill = document.getElementById("telemetryStatus");
  pill.textContent = message;
  pill.className = "pill " + (ok ? "ok" : "err");
}

function loadConfig() {
  chrome.storage.sync.get(DEFAULTS, (cfg) => {
    document.getElementById("endpoint").textContent = cfg.endpoint;
    document.getElementById("endpoint").title = cfg.endpoint;
    document.getElementById("tenant").textContent = cfg.tenantId || "unset";
  });
}

function sendTest() {
  const result = document.getElementById("result");
  result.textContent = "Sending test telemetry...";
  chrome.runtime.sendMessage(
    {
      type: "telemetry",
      body: {
        event_type: "popup_test",
        payload: { ts: new Date().toISOString() },
        source: "browser_extension",
      },
    },
    (resp) => {
      if (resp && resp.ok) {
        setStatus(true, "OK");
        result.textContent = "Test telemetry sent.";
      } else {
        setStatus(false, "Error");
        result.textContent = resp?.error || "Send failed.";
      }
    }
  );
}

function init() {
  loadConfig();
  // Probe telemetry with a HEAD/OPTIONS-like check by sending a lightweight test.
  sendTest();
  document.getElementById("test").addEventListener("click", sendTest);
  document.getElementById("options").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });
}

document.addEventListener("DOMContentLoaded", init);
