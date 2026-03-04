/**
 * AIShields Protect — Safari Content Script
 * PII detection, AI chat monitoring (same core logic as Chromium/Firefox).
 */

const PII_PATTERNS = [
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: 'Credit Card', pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g },
  { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/g },
];

const AI_CHAT_SELECTORS = [
  'textarea[data-id="root"]', '#prompt-textarea', 'div[contenteditable="true"]',
  '.ProseMirror', 'textarea.w-full',
];

function monitorInputs() {
  AI_CHAT_SELECTORS.forEach(sel => {
    document.querySelectorAll(sel).forEach(el => {
      if (el._aishieldsMonitored) return;
      el._aishieldsMonitored = true;
      el.addEventListener('paste', (e) => {
        const text = e.clipboardData?.getData('text') || '';
        const found = PII_PATTERNS.filter(p => p.pattern.test(text));
        if (found.length) {
          const banner = document.createElement('div');
          banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999999;padding:12px;background:#991b1b;color:#fff;text-align:center;font-family:system-ui;font-size:14px;';
          banner.textContent = `AIShields: PII detected (${found.map(f=>f.name).join(', ')})`;
          document.body.prepend(banner);
          setTimeout(() => banner.remove(), 6000);
        }
      });
    });
  });

  // Notify background of AI domain visits
  const host = location.hostname;
  if (['chatgpt.com','claude.ai','gemini.google.com','copilot.microsoft.com','poe.com'].includes(host)) {
    browser.runtime.sendMessage({ type: 'aiActivity', domain: host });
  }
}

const obs = new MutationObserver(monitorInputs);
obs.observe(document.documentElement, { childList: true, subtree: true });
document.addEventListener('DOMContentLoaded', monitorInputs);
