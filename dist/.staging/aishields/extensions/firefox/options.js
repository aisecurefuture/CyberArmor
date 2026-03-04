browser.storage.sync.get('aishields_config').then(data => {
  const cfg = data.aishields_config || {};
  document.getElementById('url').value = cfg.controlPlaneUrl || '';
  document.getElementById('key').value = cfg.apiKey || '';
  document.getElementById('tenant').value = cfg.tenantId || 'default';
});
document.getElementById('save').addEventListener('click', () => {
  browser.storage.sync.set({
    aishields_config: {
      controlPlaneUrl: document.getElementById('url').value,
      apiKey: document.getElementById('key').value,
      tenantId: document.getElementById('tenant').value,
    }
  }).then(() => { document.getElementById('msg').textContent = 'Saved!'; });
});
