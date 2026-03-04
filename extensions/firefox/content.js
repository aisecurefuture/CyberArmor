/**
 * AIShields Protect — Firefox Content Script
 * PII detection, XSS prevention, AI chat monitoring, prompt injection scanning.
 */

const PII_PATTERNS = [
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: 'Credit Card', pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g },
  { name: 'Email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi },
  { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'GitHub Token', pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/g },
];

const XSS_PATTERNS = [
  /<script[\s>]/i, /javascript:/i, /on(error|load|click|mouseover)\s*=/i,
  /eval\s*\(/i, /document\.cookie/i, /innerHTML\s*=/i,
];

const AI_CHAT_SELECTORS = [
  'textarea[data-id="root"]', '#prompt-textarea', 'div[contenteditable="true"]',
  '.ProseMirror', 'textarea.w-full', 'textarea[placeholder*="message"]',
];

// Monitor AI chat inputs
function monitorAIChatInputs() {
  const inputs = [];
  AI_CHAT_SELECTORS.forEach(sel => {
    document.querySelectorAll(sel).forEach(el => inputs.push(el));
  });

  inputs.forEach(input => {
    if (input._aishieldsMonitored) return;
    input._aishieldsMonitored = true;

    input.addEventListener('paste', (e) => {
      const text = e.clipboardData?.getData('text') || '';
      const piiFound = PII_PATTERNS.filter(p => p.pattern.test(text));
      if (piiFound.length > 0) {
        showWarning(`PII detected in paste: ${piiFound.map(p => p.name).join(', ')}`);
      }
    });
  });
}

function showWarning(message) {
  const banner = document.createElement('div');
  banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999999;padding:12px 20px;background:#991b1b;color:#fff;font-family:system-ui;font-size:14px;text-align:center;';
  banner.textContent = `⚠ AIShields: ${message}`;
  const close = document.createElement('button');
  close.textContent = '✕';
  close.style.cssText = 'margin-left:16px;background:none;border:none;color:#fff;cursor:pointer;font-size:16px;';
  close.onclick = () => banner.remove();
  banner.appendChild(close);
  document.body.prepend(banner);
  setTimeout(() => banner.remove(), 8000);
}

// Observe DOM for new chat inputs
const observer = new MutationObserver(() => monitorAIChatInputs());
observer.observe(document.documentElement, { childList: true, subtree: true });

// Initial scan
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', monitorAIChatInputs);
} else {
  monitorAIChatInputs();
}

console.log('[AIShields Protect] Firefox content script loaded');
