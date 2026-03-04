/**
 * AIShields Browser Protection - Content Script
 * Injected into all web pages for real-time protection.
 *
 * Features:
 * - PII detection and redaction in form fields
 * - AI prompt monitoring on AI chat interfaces
 * - Promptware detection (malicious prompts in web pages)
 * - XSS and command injection detection
 * - Copy/paste interception for sensitive data
 * - Policy enforcement overlays (warn/block banners)
 * - Data classification labels
 */

(function () {
  "use strict";

  // --- PII Patterns ---
  const PII_PATTERNS = [
    { label: "ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
    { label: "phone", pattern: /\b\d{10}\b/g },
    { label: "email", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi },
    { label: "credit_card", pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g },
    { label: "bank_account", pattern: /\b\d{9,12}\b/g },
    { label: "drivers_license", pattern: /\b[A-Z]{1,2}\d{4,8}\b/g },
    { label: "iban", pattern: /\b[A-Z]{2}\d{2}[A-Za-z0-9]{4}\d{14}\b/g },
    { label: "api_key", pattern: /\b(?:sk-|pk_|api[_-]?key)[A-Za-z0-9]{16,}\b/gi },
    { label: "aws_key", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
    { label: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
    { label: "private_key", pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g },
    { label: "password_field", pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S+/gi },
  ];

  // --- XSS / Injection Patterns ---
  const XSS_PATTERNS = [
    /<script\b[^>]*>[\s\S]*?<\/script>/gi,
    /javascript\s*:/gi,
    /on(?:load|error|click|mouseover|focus|blur|submit)\s*=/gi,
    /\beval\s*\(/gi,
    /\bdocument\.(?:cookie|write|location)/gi,
    /\bwindow\.(?:location|open)\s*=/gi,
    /\balert\s*\(/gi,
    /\bconfirm\s*\(/gi,
    /\bprompt\s*\(/gi,
  ];

  const CMD_INJECTION_PATTERNS = [
    /[;|&`]\s*(?:cat|ls|rm|wget|curl|bash|sh|python|perl|nc|netcat)\b/gi,
    /\$\(.*\)/g,
    /`[^`]*`/g,
    /\|\s*(?:bash|sh|zsh|cmd|powershell)/gi,
  ];

  // --- Prompt Injection Patterns (for AI interfaces) ---
  const PROMPT_INJECTION_PATTERNS = [
    /ignore\s+(all\s+)?previous\s+instructions/i,
    /disregard\s+(the\s+)?(system|previous)\s+prompt/i,
    /\bjailbreak\b/i,
    /\bbegin\s+(?:new\s+)?system\s+prompt/i,
    /\bdeveloper\s+mode\b/i,
    /\bdisable\s+safety\b/i,
    /\bexfiltrate\b/i,
    /\bDAN\s+mode\b/i,
    /\bbypass\s+.*?(?:safety|content)\s+filter/i,
    /\bact\s+as\s+(?:an?\s+)?unrestricted/i,
  ];

  // --- AI Chat Interface Selectors ---
  const AI_CHAT_SELECTORS = [
    'textarea[data-id="root"]',           // ChatGPT
    'div[contenteditable="true"]',         // Claude, various
    'textarea.prompt-textarea',            // ChatGPT
    '#prompt-textarea',                    // ChatGPT
    'textarea[placeholder*="message"]',    // Generic AI chats
    'textarea[placeholder*="Ask"]',        // Generic AI chats
    '.ProseMirror[contenteditable]',       // Various editors
    'textarea[name="q"]',                  // Search/AI
  ];

  let config = {};
  let userId = null;

  // --- Initialization ---

  function init() {
    loadConfig();
    generateUserId();
    setupInputListeners();
    setupPasteInterception();
    scanQueryStrings();
    setupMutationObserver();
    scanPageForPromptware();
    sendTelemetry("page_visit", { url: window.location.href, title: document.title });
  }

  function loadConfig() {
    if (typeof chrome !== "undefined" && chrome.storage) {
      chrome.storage.sync.get(null, (cfg) => {
        config = cfg || {};
      });
    }
  }

  function generateUserId() {
    if (typeof chrome !== "undefined" && chrome.storage) {
      chrome.storage.local.get(["aishields_user_id"], (data) => {
        if (data.aishields_user_id) {
          userId = data.aishields_user_id;
        } else {
          userId = "user-" + crypto.randomUUID();
          chrome.storage.local.set({ aishields_user_id: userId });
        }
      });
    }
  }

  // --- PII Detection ---

  function detectPII(text) {
    const findings = [];
    for (const { label, pattern } of PII_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      const matches = text.match(regex);
      if (matches) {
        findings.push({ label, count: matches.length });
      }
    }
    return findings;
  }

  function redactPII(text) {
    let redacted = text;
    for (const { label, pattern } of PII_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      redacted = redacted.replace(regex, `[REDACTED-${label}]`);
    }
    return redacted;
  }

  // --- XSS Detection ---

  function detectXSS(text) {
    const findings = [];
    for (const pattern of XSS_PATTERNS) {
      if (pattern.test(text)) {
        findings.push({ type: "xss", pattern: pattern.source });
      }
    }
    for (const pattern of CMD_INJECTION_PATTERNS) {
      if (pattern.test(text)) {
        findings.push({ type: "command_injection", pattern: pattern.source });
      }
    }
    return findings;
  }

  // --- Prompt Injection Detection ---

  function detectPromptInjection(text) {
    const matches = [];
    for (const pattern of PROMPT_INJECTION_PATTERNS) {
      if (pattern.test(text)) {
        matches.push(pattern.source);
      }
    }
    return matches;
  }

  // --- Promptware Detection ---

  function scanPageForPromptware() {
    const bodyText = document.body ? document.body.innerText : "";
    const injections = detectPromptInjection(bodyText);
    if (injections.length > 0) {
      sendTelemetry("promptware_detected", {
        url: window.location.href,
        patterns: injections.slice(0, 5),
        textLength: bodyText.length,
      });
      showWarningBanner("Promptware detected on this page. Malicious AI prompts found in page content.");
    }
  }

  // --- Input Monitoring ---

  function setupInputListeners() {
    document.addEventListener("input", handleInput, true);
    document.addEventListener("change", handleInput, true);
    // Monitor AI chat interfaces
    setTimeout(monitorAIChatInputs, 2000);
  }

  function handleInput(event) {
    const el = event.target;
    if (!el || (!el.value && !el.textContent)) return;
    const text = el.value || el.textContent;
    if (text.length < 3) return;

    // PII detection
    if (config.redactPIIEnabled !== false) {
      const piiFindings = detectPII(text);
      if (piiFindings.length > 0) {
        sendTelemetry("pii_detected", {
          url: window.location.href,
          field: el.name || el.id || el.className || "unknown",
          findings: piiFindings,
          redacted: redactPII(text.substring(0, 200)),
        });
        highlightField(el, "pii");
      }
    }

    // XSS detection
    const xssFindings = detectXSS(text);
    if (xssFindings.length > 0) {
      sendTelemetry("xss_detected", {
        url: window.location.href,
        field: el.name || el.id || "unknown",
        findings: xssFindings,
      });
      showWarningBanner("Potential XSS/injection detected in form input.");
    }
  }

  function monitorAIChatInputs() {
    for (const selector of AI_CHAT_SELECTORS) {
      const elements = document.querySelectorAll(selector);
      elements.forEach((el) => {
        if (el.__aishields_monitored) return;
        el.__aishields_monitored = true;

        const handler = debounce(() => {
          const text = el.value || el.textContent || "";
          if (text.length < 10) return;

          // Check for prompt injection in AI inputs
          const injections = detectPromptInjection(text);
          if (injections.length > 0) {
            sendTelemetry("prompt_injection_attempt", {
              url: window.location.href,
              patterns: injections,
              textPreview: text.substring(0, 100),
            });

            // Check policy
            if (typeof chrome !== "undefined" && chrome.runtime) {
              chrome.runtime.sendMessage({
                type: "evaluate_policy",
                context: {
                  request: { url: window.location.href, type: "prompt_submission" },
                  content: { has_injection: true, injection_patterns: injections },
                },
              }, (resp) => {
                if (resp?.result?.matched && resp.result.action === "block") {
                  el.value = "";
                  el.textContent = "";
                  showWarningBanner("Prompt injection blocked by security policy.");
                } else if (resp?.result?.matched && resp.result.action === "warn") {
                  showWarningBanner("Warning: Prompt injection patterns detected.");
                }
              });
            }
          }

          // Check for PII in AI prompts
          const piiFindings = detectPII(text);
          if (piiFindings.length > 0) {
            sendTelemetry("pii_in_ai_prompt", {
              url: window.location.href,
              findings: piiFindings,
            });
            showWarningBanner("Sensitive data detected in AI prompt. Consider removing PII before sending.");
          }
        }, 500);

        el.addEventListener("input", handler, true);
        el.addEventListener("keyup", handler, true);
      });
    }
  }

  // --- Paste Interception ---

  function setupPasteInterception() {
    document.addEventListener("paste", (event) => {
      const text = event.clipboardData?.getData("text/plain");
      if (!text) return;

      const piiFindings = detectPII(text);
      if (piiFindings.length > 0) {
        sendTelemetry("pii_paste_detected", {
          url: window.location.href,
          findings: piiFindings,
        });
      }
    }, true);
  }

  // --- Query String Scanning ---

  function scanQueryStrings() {
    const qs = window.location.search + window.location.hash;
    if (qs.length < 5) return;
    const piiFindings = detectPII(decodeURIComponent(qs));
    if (piiFindings.length > 0) {
      sendTelemetry("pii_in_url", {
        url: window.location.href,
        findings: piiFindings,
      });
    }
  }

  // --- Mutation Observer ---

  function setupMutationObserver() {
    const observer = new MutationObserver(
      debounce(() => {
        monitorAIChatInputs();
      }, 1000)
    );
    if (document.body) {
      observer.observe(document.body, { childList: true, subtree: true });
    }
  }

  // --- UI Overlays ---

  function showWarningBanner(message) {
    if (document.getElementById("aishields-warning-banner")) return;
    const banner = document.createElement("div");
    banner.id = "aishields-warning-banner";
    banner.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      background: linear-gradient(135deg, #ff6b35 0%, #f72c25 100%);
      color: white; padding: 12px 20px; font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 14px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.3);
      display: flex; align-items: center; justify-content: center; gap: 10px;
    `;
    banner.innerHTML = `
      <span style="font-size:18px">&#x1f6e1;</span>
      <span>${escapeHtml(message)}</span>
      <button onclick="this.parentElement.remove()" style="
        background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.4);
        color: white; padding: 4px 12px; border-radius: 4px; cursor: pointer;
        font-size: 12px; margin-left: 10px;
      ">Dismiss</button>
    `;
    document.body.prepend(banner);
    setTimeout(() => banner.remove(), 15000);
  }

  function highlightField(el, type) {
    el.style.outline = type === "pii" ? "2px solid #ff6b35" : "2px solid #f72c25";
    el.title = `AIShields: ${type === "pii" ? "Sensitive data detected" : "Security risk detected"}`;
  }

  // --- Telemetry ---

  function sendTelemetry(eventType, payload) {
    if (typeof chrome !== "undefined" && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: "telemetry",
        body: {
          event_type: eventType,
          payload: { ...payload, user_id: userId },
          source: "browser_extension",
        },
      });
    }
  }

  // --- Utilities ---

  function debounce(fn, ms) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), ms);
    };
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // --- Start ---
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
