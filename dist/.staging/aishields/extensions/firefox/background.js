/**
 * AIShields Protect — Firefox Background Script
 * Uses browser.* APIs (WebExtension standard) for policy sync, AI monitoring, phishing protection.
 */

const AI_DOMAINS = new Set([
  'api.openai.com','api.anthropic.com','generativelanguage.googleapis.com',
  'api.cohere.ai','api.mistral.ai','api-inference.huggingface.co',
  'api.together.xyz','api.replicate.com','api.groq.com',
  'chatgpt.com','chat.openai.com','claude.ai','gemini.google.com',
  'copilot.microsoft.com','poe.com','perplexity.ai','huggingface.co',
]);

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /you\s+are\s+now\s+(a|an|in)/i,
  /system\s*:\s*you\s+are/i,
  /<\s*(system|prompt|instruction)\s*>/i,
  /jailbreak|DAN\s+mode|bypass\s+filter/i,
  /forget\s+(everything|all|your)/i,
];

let policies = [];
let config = { controlPlaneUrl: 'http://localhost:8000', apiKey: '', syncInterval: 60000 };

// Load config
browser.storage.sync.get(['aishields_config', 'aishields_policies']).then(data => {
  if (data.aishields_config) config = { ...config, ...data.aishields_config };
  if (data.aishields_policies) policies = data.aishields_policies;
  startPolicySync();
});

function startPolicySync() {
  if (!config.controlPlaneUrl || !config.apiKey) return;
  setInterval(syncPolicies, config.syncInterval);
  syncPolicies();
}

async function syncPolicies() {
  try {
    const resp = await fetch(`${config.controlPlaneUrl}/policies/default`, {
      headers: { 'x-api-key': config.apiKey }
    });
    if (resp.ok) {
      policies = await resp.json();
      browser.storage.local.set({ aishields_policies: policies });
    }
  } catch (e) { console.debug('[AIShields] Policy sync failed:', e.message); }
}

// Intercept AI API requests
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    try {
      const url = new URL(details.url);
      if (!AI_DOMAINS.has(url.hostname)) return {};

      // Log AI request
      console.log(`[AIShields] AI request: ${details.method} ${url.hostname}${url.pathname}`);

      // Check request body for prompt injection
      if (details.requestBody && details.requestBody.raw) {
        const decoder = new TextDecoder();
        const bodyText = details.requestBody.raw.map(r => decoder.decode(r.bytes)).join('');
        for (const pat of PROMPT_INJECTION_PATTERNS) {
          if (pat.test(bodyText)) {
            console.warn('[AIShields] Prompt injection detected in request to', url.hostname);
            // In block mode, cancel the request
            const blockPolicy = policies.find(p => p.action === 'block' && p.enabled);
            if (blockPolicy) {
              return { cancel: true };
            }
            break;
          }
        }
      }
    } catch (e) { console.debug('[AIShields] Inspection error:', e); }
    return {};
  },
  { urls: ['<all_urls>'] },
  ['blocking', 'requestBody']
);

// Message handling from content script / popup
browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'getStatus') {
    sendResponse({ active: true, policies: policies.length, config });
  } else if (msg.type === 'getPolicies') {
    sendResponse({ policies });
  }
  return true;
});

console.log('[AIShields Protect] Firefox extension loaded');
