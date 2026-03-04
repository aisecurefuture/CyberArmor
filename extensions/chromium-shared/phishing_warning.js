/**
 * AIShields Protect - Phishing Warning Page Logic
 * Handles the interstitial warning page displayed when phishing is detected.
 * Provides go-back, proceed, report, and allowlist functionality.
 */

(function () {
  "use strict";

  // --- Parse URL Parameters ---

  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get("u") || params.get("url") || "Unknown URL";
  const reason = params.get("reason") || "phishing_detected";

  // --- Reason Descriptions ---

  const REASON_MAP = {
    phishing_detected: {
      title: "Phishing or suspicious site detected",
      reasons: [
        "The URL matches known phishing patterns",
        "This site may attempt to steal your credentials",
        "The domain appears to impersonate a legitimate service",
      ],
    },
    ip_address_url: {
      title: "Direct IP address access detected",
      reasons: [
        "The URL uses a raw IP address instead of a domain name",
        "Legitimate sites rarely use IP addresses in URLs",
        "This pattern is commonly used in phishing attacks",
      ],
    },
    credential_url: {
      title: "Credential harvesting URL detected",
      reasons: [
        "The URL contains embedded credentials (user@host format)",
        "This technique is used to obscure the real destination",
        "Your browser may be redirected to a malicious site",
      ],
    },
    idn_homograph: {
      title: "IDN homograph attack detected",
      reasons: [
        "The domain uses internationalized characters that resemble ASCII characters",
        "This technique makes phishing domains appear identical to legitimate ones",
        "The actual domain is different from what it appears to be",
      ],
    },
    insecure_login: {
      title: "Insecure login page detected",
      reasons: [
        "This login page is served over unencrypted HTTP",
        "Your credentials could be intercepted in transit",
        "Legitimate login pages should always use HTTPS",
      ],
    },
    policy_block: {
      title: "Blocked by organizational security policy",
      reasons: [
        "Your organization's security policy restricts access to this site",
        "This may be categorized as a risky or unauthorized service",
        "Contact your security team if you believe this is an error",
      ],
    },
  };

  // --- DOM Elements ---

  const els = {
    blockedUrl: document.getElementById("blocked-url"),
    blockReason: document.getElementById("block-reason"),
    warningReasons: document.getElementById("warning-reasons"),
    btnGoBack: document.getElementById("btn-go-back"),
    btnReport: document.getElementById("btn-report"),
    btnProceed: document.getElementById("btn-proceed"),
    chkAllowlist: document.getElementById("chk-allowlist"),
    timestamp: document.getElementById("timestamp"),
  };

  // --- Initialization ---

  function init() {
    // Display blocked URL (truncated for safety)
    const displayUrl = blockedUrl.length > 120 ? blockedUrl.substring(0, 120) + "..." : blockedUrl;
    els.blockedUrl.textContent = displayUrl;
    els.blockedUrl.title = blockedUrl;

    // Display reason
    const reasonInfo = REASON_MAP[reason] || REASON_MAP.phishing_detected;
    els.blockReason.textContent = reasonInfo.title;
    els.warningReasons.innerHTML = reasonInfo.reasons
      .map((r) => `<li>${escapeHtml(r)}</li>`)
      .join("");

    // Timestamp
    els.timestamp.textContent = new Date().toLocaleString();

    // Send telemetry for the block event
    sendTelemetry("phishing_warning_shown", {
      blockedUrl,
      reason,
    });

    setupEventListeners();
  }

  // --- Event Handlers ---

  function setupEventListeners() {
    // Go back
    els.btnGoBack.addEventListener("click", () => {
      sendTelemetry("phishing_warning_go_back", { blockedUrl, reason });

      if (window.history.length > 1) {
        window.history.back();
      } else {
        // Navigate to a safe page
        window.location.href = "about:newtab";
      }
    });

    // Report
    els.btnReport.addEventListener("click", () => {
      sendTelemetry("phishing_site_reported", {
        blockedUrl,
        reason,
        reportedAt: new Date().toISOString(),
      });

      els.btnReport.textContent = "Reported - Thank You";
      els.btnReport.disabled = true;
      els.btnReport.classList.add("btn-primary");
      els.btnReport.classList.remove("btn-outline");
    });

    // Proceed (risky)
    els.btnProceed.addEventListener("click", () => {
      // Check if the user wants to allowlist
      const shouldAllowlist = els.chkAllowlist.checked;

      sendTelemetry("phishing_warning_bypassed", {
        blockedUrl,
        reason,
        allowlisted: shouldAllowlist,
      });

      if (shouldAllowlist) {
        try {
          const domain = new URL(blockedUrl).hostname;
          chrome.runtime.sendMessage({
            type: "phishing_allowlist_domain",
            domain,
          });
        } catch {
          // URL parsing failed
        }
      }

      // Navigate to the blocked URL
      window.location.href = blockedUrl;
    });
  }

  // --- Telemetry ---

  function sendTelemetry(eventType, payload) {
    if (typeof chrome !== "undefined" && chrome.runtime) {
      try {
        chrome.runtime.sendMessage({
          type: "telemetry",
          body: {
            event_type: eventType,
            payload,
            source: "phishing_warning",
          },
        });
      } catch {
        // Extension context may be invalidated
      }
    }
  }

  // --- Utilities ---

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str || "";
    return div.innerHTML;
  }

  // --- Start ---
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
