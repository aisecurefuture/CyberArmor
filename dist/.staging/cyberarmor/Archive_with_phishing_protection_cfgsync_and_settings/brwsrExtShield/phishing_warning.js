(function () {
  function getOriginalUrl() {
    const u = new URL(window.location.href);
    const param = u.searchParams.get('u');
    if (!param) return null;
    try {
      return decodeURIComponent(param);
    } catch (e) {
      // If it wasn't encoded, fall back.
      return param;
    }
  }

  function getHostname(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return null;
    }
  }

  const original = getOriginalUrl();
  const destEl = document.getElementById('dest');
  destEl.textContent = original || '(unknown)';

  document.getElementById('goBack').addEventListener('click', () => {
    try {
      history.back();
    } catch {
      window.close();
    }
  });

  document.getElementById('continue').addEventListener('click', async () => {
    if (!original) return;

    const host = getHostname(original);
    if (!host) {
      // If we can't parse it, just open in a new tab.
      chrome.tabs.create({ url: original });
      return;
    }

    // Add to allowlist then open.
    chrome.runtime.sendMessage({ type: 'phishing_allowlist_domain', domain: host }, (res) => {
      // Best-effort; even if it fails we still allow the user to proceed.
      chrome.tabs.create({ url: original });
    });
  });
})();
