browser.runtime.sendMessage({ type: 'getStatus' }).then(data => {
  document.getElementById('policyCount').textContent = data?.policies || 0;
  if (!data?.active) {
    document.getElementById('statusDot').className = 'dot red';
    document.getElementById('statusText').textContent = 'Inactive';
  }
});
document.getElementById('optionsLink').addEventListener('click', () => {
  browser.runtime.openOptionsPage();
});
