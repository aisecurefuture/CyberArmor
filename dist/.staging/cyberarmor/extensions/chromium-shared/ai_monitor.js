/**
 * AIShields Protect - Dedicated AI Monitoring Module
 * Injected into AI service pages (ChatGPT, Claude, Gemini, Copilot, etc.)
 *
 * Features:
 * - Intercept AI chat messages (prompts and completions)
 * - Track prompt/completion token estimates
 * - Detect prompt injection patterns in real-time
 * - Monitor AI file uploads and scan for sensitive data
 * - Enforce DLP policies before data reaches AI services
 * - Integrate with the policy engine for real-time enforcement
 */

(function () {
  "use strict";

  // Verify policy engine is available
  const PolicyEngine = typeof AIShieldsPolicyEngine !== "undefined" ? AIShieldsPolicyEngine : null;

  // --- Configuration ---

  let config = {
    aiMonitoringEnabled: true,
    promptInjectionDetection: true,
    aiFileUploadMonitoring: true,
    logAIPrompts: false,
    autoRedactPII: true,
    actionMode: "warn",
    disabledAIServices: [],
  };

  let currentService = null;
  let sessionStats = {
    promptCount: 0,
    completionCount: 0,
    injectionAttempts: 0,
    piiDetections: 0,
    filesScanned: 0,
    sessionStart: Date.now(),
  };

  // --- AI Service Detection ---

  const SERVICE_SELECTORS = {
    chatgpt: {
      inputSelector: '#prompt-textarea, textarea[data-id="root"], textarea.prompt-textarea',
      submitSelector: 'button[data-testid="send-button"], button[data-testid="fruitjuice-send-button"]',
      messageSelector: '[data-message-author-role]',
      userMessageAttr: { key: "data-message-author-role", value: "user" },
      assistantMessageAttr: { key: "data-message-author-role", value: "assistant" },
      fileInputSelector: 'input[type="file"]',
    },
    claude: {
      inputSelector: 'div[contenteditable="true"].ProseMirror, div[contenteditable="true"]',
      submitSelector: 'button[aria-label="Send Message"], button[type="submit"]',
      messageSelector: '[data-testid="user-message"], [data-testid="ai-message"]',
      userMessageAttr: { key: "data-testid", value: "user-message" },
      assistantMessageAttr: { key: "data-testid", value: "ai-message" },
      fileInputSelector: 'input[type="file"]',
    },
    gemini: {
      inputSelector: '.ql-editor, rich-textarea .textarea, textarea[placeholder*="Enter"]',
      submitSelector: 'button.send-button, button[aria-label="Send message"]',
      messageSelector: '.message-content, .response-content',
      userMessageAttr: null,
      assistantMessageAttr: null,
      fileInputSelector: 'input[type="file"]',
    },
    copilot: {
      inputSelector: '#searchbox, textarea[name="searchbox"], .cib-serp-main textarea',
      submitSelector: 'button[aria-label="Submit"]',
      messageSelector: '.ac-adaptiveCard',
      userMessageAttr: null,
      assistantMessageAttr: null,
      fileInputSelector: 'input[type="file"]',
    },
    generic: {
      inputSelector: 'textarea[placeholder*="message"], textarea[placeholder*="Message"], textarea[placeholder*="Ask"], div[contenteditable="true"]',
      submitSelector: 'button[type="submit"], button:has(svg)',
      messageSelector: '.message, .chat-message',
      userMessageAttr: null,
      assistantMessageAttr: null,
      fileInputSelector: 'input[type="file"]',
    },
  };

  // --- Initialization ---

  function init() {
    loadConfig().then(() => {
      detectCurrentService();
      if (!config.aiMonitoringEnabled) return;
      if (currentService && config.disabledAIServices.includes(currentService.id)) return;

      setupPromptInterception();
      setupCompletionMonitoring();
      setupFileUploadMonitoring();
      setupNetworkInterception();
      setupMutationObserver();

      sendTelemetry("ai_session_start", {
        service: currentService?.name || "unknown",
        domain: window.location.hostname,
      });
    });
  }

  async function loadConfig() {
    return new Promise((resolve) => {
      if (typeof chrome !== "undefined" && chrome.storage) {
        chrome.storage.sync.get(null, (cfg) => {
          Object.assign(config, cfg);
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  function detectCurrentService() {
    const hostname = window.location.hostname.toLowerCase();
    if (PolicyEngine) {
      const svc = PolicyEngine.identifyAIService(hostname);
      if (svc) {
        currentService = svc;
        return;
      }
    }
    // Fallback matching
    if (hostname.includes("openai.com") || hostname.includes("chatgpt.com")) {
      currentService = { id: "chatgpt", name: "ChatGPT" };
    } else if (hostname.includes("claude.ai")) {
      currentService = { id: "claude", name: "Claude" };
    } else if (hostname.includes("gemini.google.com") || hostname.includes("bard.google.com")) {
      currentService = { id: "gemini", name: "Gemini" };
    } else if (hostname.includes("copilot.microsoft.com")) {
      currentService = { id: "copilot", name: "Copilot" };
    } else {
      currentService = { id: "generic", name: "AI Service" };
    }
  }

  // --- Prompt Interception ---

  function setupPromptInterception() {
    const serviceConfig = SERVICE_SELECTORS[currentService?.id] || SERVICE_SELECTORS.generic;

    // Monitor input fields
    const attachInputMonitor = () => {
      const inputs = document.querySelectorAll(serviceConfig.inputSelector);
      inputs.forEach((input) => {
        if (input.__aishields_ai_monitored) return;
        input.__aishields_ai_monitored = true;

        // Real-time typing analysis with debounce
        input.addEventListener("input", debounce(() => {
          const text = getInputText(input);
          if (text.length < 5) return;
          analyzePromptContent(text, input);
        }, 300), true);

        // Catch submit via Enter key
        input.addEventListener("keydown", (e) => {
          if (e.key === "Enter" && !e.shiftKey) {
            const text = getInputText(input);
            if (text.length >= 3) {
              handlePromptSubmission(text);
            }
          }
        }, true);
      });

      // Monitor submit buttons
      const submitBtns = document.querySelectorAll(serviceConfig.submitSelector);
      submitBtns.forEach((btn) => {
        if (btn.__aishields_submit_monitored) return;
        btn.__aishields_submit_monitored = true;

        btn.addEventListener("click", () => {
          const input = document.querySelector(serviceConfig.inputSelector);
          if (input) {
            const text = getInputText(input);
            if (text.length >= 3) {
              handlePromptSubmission(text);
            }
          }
        }, true);
      });
    };

    attachInputMonitor();
    // Re-attach after DOM changes (SPAs re-render)
    setInterval(attachInputMonitor, 3000);
  }

  function getInputText(element) {
    if (element.tagName === "TEXTAREA" || element.tagName === "INPUT") {
      return element.value || "";
    }
    // contenteditable div
    return element.innerText || element.textContent || "";
  }

  function analyzePromptContent(text, inputElement) {
    // Check for prompt injection
    if (config.promptInjectionDetection && PolicyEngine) {
      const injections = PolicyEngine.detectPromptInjection(text);
      if (injections.length > 0) {
        sessionStats.injectionAttempts++;
        const severity = injections[0].severity;

        sendTelemetry("prompt_injection_realtime", {
          service: currentService?.name,
          patterns: injections.map((i) => i.id),
          severity,
          textLength: text.length,
        });

        if (config.actionMode === "block" && (severity === "critical" || severity === "high")) {
          blockInput(inputElement, "Prompt injection detected and blocked by security policy.");
          return;
        }
        if (config.actionMode === "warn" || config.actionMode === "block") {
          showInlineWarning(inputElement, `Prompt injection detected: ${injections[0].description}`);
        }
      }
    }

    // Check for PII / sensitive data
    if (PolicyEngine) {
      const classified = PolicyEngine.classifyData(text);
      const sensitive = classified.filter((c) => c.severity === "critical" || c.severity === "high");
      if (sensitive.length > 0) {
        sessionStats.piiDetections++;

        sendTelemetry("pii_in_ai_prompt_realtime", {
          service: currentService?.name,
          labels: sensitive.map((s) => s.label),
          severity: sensitive[0].severity,
        });

        if (config.actionMode === "block") {
          showInlineWarning(inputElement, `Sensitive data detected (${sensitive.map((s) => s.label).join(", ")}). Remove before sending.`);
        } else if (config.actionMode === "warn") {
          showInlineWarning(inputElement, `Warning: Sensitive data detected (${sensitive.map((s) => s.label).join(", ")})`);
        }
      }
    }
  }

  function handlePromptSubmission(text) {
    sessionStats.promptCount++;

    // Run policy evaluation
    if (PolicyEngine && typeof chrome !== "undefined" && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: "evaluate_policy",
        context: {
          request: {
            url: window.location.href,
            type: "ai_prompt_submission",
            ai_service: currentService?.id,
          },
          content: {
            text_length: text.length,
            has_pii: (PolicyEngine.detectPII(text) || []).length > 0,
            has_injection: (PolicyEngine.detectPromptInjection(text) || []).length > 0,
          },
        },
      }, (resp) => {
        if (resp?.result?.matched) {
          handlePolicyAction(resp.result);
        }
      });
    }

    // Send telemetry for the prompt
    const payload = {
      service: currentService?.name,
      domain: window.location.hostname,
      promptLength: text.length,
      estimatedTokens: estimateTokens(text),
      promptNumber: sessionStats.promptCount,
    };

    if (config.logAIPrompts) {
      payload.promptText = config.autoRedactPII && PolicyEngine
        ? PolicyEngine.redactPII(text)
        : text.substring(0, 500);
    }

    sendTelemetry("ai_prompt_submitted", payload);
  }

  // --- Completion Monitoring ---

  function setupCompletionMonitoring() {
    const serviceConfig = SERVICE_SELECTORS[currentService?.id] || SERVICE_SELECTORS.generic;
    let lastCompletionCount = 0;

    const checkForNewCompletions = () => {
      if (!serviceConfig.messageSelector) return;
      const messages = document.querySelectorAll(serviceConfig.messageSelector);
      if (messages.length > lastCompletionCount) {
        const newMessages = Array.from(messages).slice(lastCompletionCount);
        for (const msg of newMessages) {
          // Determine if it is a user or assistant message
          const isAssistant = serviceConfig.assistantMessageAttr
            ? msg.getAttribute(serviceConfig.assistantMessageAttr.key) === serviceConfig.assistantMessageAttr.value
            : !msg.classList.contains("user");

          if (isAssistant) {
            sessionStats.completionCount++;
            const text = msg.innerText || msg.textContent || "";

            // Scan completions for sensitive data leaks
            if (PolicyEngine && text.length > 10) {
              const threats = PolicyEngine.detectThreats(text);
              if (threats.hasThreats) {
                sendTelemetry("ai_completion_threat", {
                  service: currentService?.name,
                  threats: {
                    promptInjection: threats.promptInjection.length,
                    xss: threats.xss.length,
                    commandInjection: threats.commandInjection.length,
                  },
                  severity: threats.highestSeverity,
                });
              }

              const classified = PolicyEngine.classifyData(text);
              const sensitive = classified.filter((c) => c.severity === "critical" || c.severity === "high");
              if (sensitive.length > 0) {
                sendTelemetry("ai_completion_sensitive_data", {
                  service: currentService?.name,
                  labels: sensitive.map((s) => s.label),
                });
              }
            }

            sendTelemetry("ai_completion_received", {
              service: currentService?.name,
              completionLength: text.length,
              estimatedTokens: estimateTokens(text),
              completionNumber: sessionStats.completionCount,
            });
          }
        }
        lastCompletionCount = messages.length;
      }
    };

    // Poll for new messages periodically
    setInterval(checkForNewCompletions, 2000);
  }

  // --- File Upload Monitoring ---

  function setupFileUploadMonitoring() {
    if (!config.aiFileUploadMonitoring) return;

    const serviceConfig = SERVICE_SELECTORS[currentService?.id] || SERVICE_SELECTORS.generic;

    const monitorFileInputs = () => {
      const fileInputs = document.querySelectorAll(serviceConfig.fileInputSelector || 'input[type="file"]');
      fileInputs.forEach((input) => {
        if (input.__aishields_file_monitored) return;
        input.__aishields_file_monitored = true;

        input.addEventListener("change", async (e) => {
          const files = Array.from(e.target.files || []);
          for (const file of files) {
            sessionStats.filesScanned++;

            const fileInfo = {
              name: file.name,
              size: file.size,
              type: file.type,
              service: currentService?.name,
            };

            // Scan text-based files for sensitive data
            if (isTextFile(file) && file.size < 5 * 1024 * 1024) {
              try {
                const content = await readFileAsText(file);
                if (PolicyEngine) {
                  const classified = PolicyEngine.classifyData(content);
                  const sensitive = classified.filter((c) => c.severity === "critical" || c.severity === "high");
                  if (sensitive.length > 0) {
                    fileInfo.sensitiveData = sensitive.map((s) => ({ label: s.label, count: s.count }));

                    sendTelemetry("ai_file_upload_sensitive", {
                      ...fileInfo,
                      sensitiveLabels: sensitive.map((s) => s.label),
                    });

                    if (config.actionMode === "block") {
                      e.preventDefault();
                      showBanner(`File "${file.name}" contains sensitive data (${sensitive.map((s) => s.label).join(", ")}) and was blocked from upload.`, "error");
                      input.value = "";
                      return;
                    } else if (config.actionMode === "warn") {
                      showBanner(`Warning: File "${file.name}" contains sensitive data (${sensitive.map((s) => s.label).join(", ")}).`, "warning");
                    }
                  }
                }
              } catch {
                // File read failed, log but don't block
              }
            }

            sendTelemetry("ai_file_upload", fileInfo);
          }
        });
      });
    };

    monitorFileInputs();
    setInterval(monitorFileInputs, 3000);
  }

  // --- Network Interception ---

  function setupNetworkInterception() {
    // Intercept fetch requests to AI API endpoints
    const originalFetch = window.fetch;
    window.fetch = async function (...args) {
      const [resource, init] = args;
      const url = typeof resource === "string" ? resource : resource?.url || "";

      if (isAIAPIEndpoint(url) && init?.method?.toUpperCase() === "POST" && init?.body) {
        try {
          let bodyText = "";
          if (typeof init.body === "string") {
            bodyText = init.body;
          } else if (init.body instanceof FormData) {
            // Cannot easily read FormData, skip
          } else if (init.body instanceof Blob) {
            bodyText = await init.body.text();
          }

          if (bodyText) {
            analyzeAPIRequestBody(url, bodyText);
          }
        } catch {
          // Don't break the original request on analysis failure
        }
      }

      return originalFetch.apply(this, args);
    };

    // Intercept XMLHttpRequest
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
      this.__aishields_url = url;
      this.__aishields_method = method;
      return originalXHROpen.call(this, method, url, ...rest);
    };

    XMLHttpRequest.prototype.send = function (body) {
      if (
        this.__aishields_method?.toUpperCase() === "POST" &&
        isAIAPIEndpoint(this.__aishields_url) &&
        typeof body === "string"
      ) {
        analyzeAPIRequestBody(this.__aishields_url, body);
      }
      return originalXHRSend.call(this, body);
    };
  }

  function isAIAPIEndpoint(url) {
    if (!url) return false;
    const apiPatterns = [
      /api\.openai\.com/i,
      /api\.anthropic\.com/i,
      /generativelanguage\.googleapis\.com/i,
      /api\.mistral\.ai/i,
      /api\.cohere\.ai/i,
      /api\.perplexity\.ai/i,
      /api\.together\.xyz/i,
      /api\.groq\.com/i,
      /chatgpt\.com\/backend-api/i,
      /claude\.ai\/api/i,
    ];
    return apiPatterns.some((p) => p.test(url));
  }

  function analyzeAPIRequestBody(url, bodyText) {
    try {
      const parsed = JSON.parse(bodyText);
      const messages = parsed.messages || parsed.prompt || [];

      let fullText = "";
      if (Array.isArray(messages)) {
        fullText = messages.map((m) => m.content || "").join(" ");
      } else if (typeof messages === "string") {
        fullText = messages;
      }

      if (fullText && PolicyEngine) {
        const classified = PolicyEngine.classifyData(fullText);
        const sensitive = classified.filter((c) => c.severity === "critical" || c.severity === "high");
        if (sensitive.length > 0) {
          sendTelemetry("ai_api_request_sensitive", {
            apiUrl: url,
            service: currentService?.name,
            labels: sensitive.map((s) => s.label),
          });
        }
      }
    } catch {
      // Not JSON or parse error, skip
    }
  }

  // --- Mutation Observer ---

  function setupMutationObserver() {
    const observer = new MutationObserver(
      debounce(() => {
        // Re-attach monitors when DOM changes (SPA navigation)
        setupPromptInterception();
        setupFileUploadMonitoring();
      }, 1500)
    );

    if (document.body) {
      observer.observe(document.body, { childList: true, subtree: true });
    }
  }

  // --- Policy Enforcement ---

  function handlePolicyAction(result) {
    if (result.action === "block") {
      showBanner(`Action blocked by policy: ${result.policy}`, "error");
    } else if (result.action === "warn") {
      showBanner(`Policy warning: ${result.policy}`, "warning");
    }
  }

  // --- UI Elements ---

  function showInlineWarning(element, message) {
    // Remove existing warning
    const existing = element.parentElement?.querySelector(".aishields-inline-warning");
    if (existing) existing.remove();

    const warning = document.createElement("div");
    warning.className = "aishields-inline-warning";
    warning.style.cssText = `
      position: absolute; bottom: -30px; left: 0; right: 0; z-index: 2147483647;
      background: #fef3c7; color: #92400e; padding: 4px 10px; font-size: 12px;
      border-radius: 4px; border: 1px solid #f59e0b; font-family: -apple-system, sans-serif;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    `;
    warning.textContent = message;

    if (element.parentElement) {
      element.parentElement.style.position = "relative";
      element.parentElement.appendChild(warning);
    }

    setTimeout(() => warning.remove(), 8000);
  }

  function blockInput(element, message) {
    if (element.tagName === "TEXTAREA" || element.tagName === "INPUT") {
      element.value = "";
    } else {
      element.innerText = "";
    }
    showBanner(message, "error");
  }

  function showBanner(message, type) {
    const bannerId = "aishields-ai-monitor-banner";
    const existing = document.getElementById(bannerId);
    if (existing) existing.remove();

    const colors = {
      error: { bg: "linear-gradient(135deg, #dc2626, #991b1b)", border: "#dc2626" },
      warning: { bg: "linear-gradient(135deg, #d97706, #92400e)", border: "#d97706" },
      info: { bg: "linear-gradient(135deg, #2563eb, #1e40af)", border: "#2563eb" },
    };

    const style = colors[type] || colors.info;

    const banner = document.createElement("div");
    banner.id = bannerId;
    banner.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      background: ${style.bg}; color: white; padding: 10px 20px;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif; font-size: 13px;
      text-align: center; display: flex; align-items: center; justify-content: center; gap: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.3);
    `;
    banner.innerHTML = `
      <strong>AIShields</strong>
      <span>${escapeHtml(message)}</span>
      <button onclick="this.parentElement.remove()" style="
        background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.4);
        color: white; padding: 3px 10px; border-radius: 4px; cursor: pointer; font-size: 12px;
        margin-left: 8px;
      ">Dismiss</button>
    `;
    document.body.prepend(banner);
    setTimeout(() => banner.remove(), 12000);
  }

  // --- Telemetry ---

  function sendTelemetry(eventType, payload) {
    if (typeof chrome !== "undefined" && chrome.runtime) {
      try {
        chrome.runtime.sendMessage({
          type: "telemetry",
          body: {
            event_type: eventType,
            payload: {
              ...payload,
              sessionDuration: Math.floor((Date.now() - sessionStats.sessionStart) / 1000),
            },
            source: "ai_monitor",
          },
        });
      } catch {
        // Extension context may be invalidated
      }
    }
  }

  // --- Utilities ---

  function estimateTokens(text) {
    // Rough estimate: ~4 characters per token for English
    return Math.ceil((text || "").length / 4);
  }

  function isTextFile(file) {
    const textTypes = [
      "text/", "application/json", "application/xml", "application/javascript",
      "application/typescript", "application/x-yaml", "application/toml",
      "application/csv", "application/sql",
    ];
    const textExtensions = [
      ".txt", ".md", ".csv", ".json", ".xml", ".yaml", ".yml", ".toml",
      ".js", ".ts", ".py", ".java", ".c", ".cpp", ".h", ".cs", ".go",
      ".rb", ".rs", ".swift", ".kt", ".php", ".sql", ".sh", ".bash",
      ".html", ".css", ".scss", ".less", ".vue", ".jsx", ".tsx",
      ".env", ".ini", ".cfg", ".conf", ".log",
    ];
    if (textTypes.some((t) => (file.type || "").startsWith(t))) return true;
    return textExtensions.some((ext) => file.name.toLowerCase().endsWith(ext));
  }

  function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  }

  function debounce(fn, ms) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), ms);
    };
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str || "";
    return div.innerHTML;
  }

  // --- Cleanup ---

  window.addEventListener("beforeunload", () => {
    sendTelemetry("ai_session_end", {
      service: currentService?.name,
      stats: { ...sessionStats },
      sessionDuration: Math.floor((Date.now() - sessionStats.sessionStart) / 1000),
    });
  });

  // --- Start ---
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
