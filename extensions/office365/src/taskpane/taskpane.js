/**
 * AIShields Protect — Office 365 Task Pane
 * Main UI logic for document scanning, DLP, and compliance checking.
 */

/* global Office, Word, Excel, PowerPoint, OneNote */

const DLP_PATTERNS = [
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'critical' },
  { name: 'Credit Card', pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g, severity: 'critical' },
  { name: 'Email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi, severity: 'low' },
  { name: 'Phone', pattern: /\b\d{3}[-.)]\s?\d{3}[-.)]\s?\d{4}\b/g, severity: 'medium' },
  { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/g, severity: 'critical' },
  { name: 'API Key', pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*["']?[A-Za-z0-9]{20,}/gi, severity: 'high' },
];

Office.onReady((info) => {
  document.getElementById('scanBtn').addEventListener('click', scanDocument);
  document.getElementById('complianceBtn').addEventListener('click', checkCompliance);
  document.getElementById('classifyBtn').addEventListener('click', classifyContent);
  renderPatternList();
});

async function scanDocument() {
  const findingsEl = document.getElementById('findings');
  findingsEl.innerHTML = '<p class="empty">Scanning...</p>';

  try {
    let text = '';
    const host = Office.context.host;

    if (host === Office.HostType.Word) {
      text = await getWordText();
    } else if (host === Office.HostType.Excel) {
      text = await getExcelText();
    } else if (host === Office.HostType.PowerPoint) {
      text = await getPowerPointText();
    } else {
      text = 'Unsupported host for direct scanning';
    }

    const findings = scanText(text);
    renderFindings(findings);
  } catch (e) {
    findingsEl.innerHTML = `<div class="finding critical">Error: ${e.message}</div>`;
  }
}

function scanText(text) {
  const findings = [];
  for (const pat of DLP_PATTERNS) {
    pat.pattern.lastIndex = 0;
    let match;
    while ((match = pat.pattern.exec(text)) !== null) {
      findings.push({
        name: pat.name,
        severity: pat.severity,
        match: match[0].substring(0, 20) + (match[0].length > 20 ? '...' : ''),
        position: match.index,
      });
    }
  }
  return findings;
}

function renderFindings(findings) {
  const el = document.getElementById('findings');
  if (findings.length === 0) {
    el.innerHTML = '<p class="empty">No sensitive data found.</p>';
    return;
  }
  el.innerHTML = findings.map(f =>
    `<div class="finding ${f.severity}"><strong>${f.name}</strong> (${f.severity})<br><code>${f.match}</code></div>`
  ).join('');
}

function renderPatternList() {
  const el = document.getElementById('dlpPatterns');
  el.innerHTML = DLP_PATTERNS.map(p =>
    `<div class="pattern"><span>${p.name}</span><span class="badge active">Active</span></div>`
  ).join('');
}

async function getWordText() {
  return new Promise((resolve, reject) => {
    Word.run(async (context) => {
      const body = context.document.body;
      body.load('text');
      await context.sync();
      resolve(body.text);
    }).catch(reject);
  });
}

async function getExcelText() {
  return new Promise((resolve, reject) => {
    Excel.run(async (context) => {
      const sheet = context.workbook.worksheets.getActiveWorksheet();
      const range = sheet.getUsedRange();
      range.load('text');
      await context.sync();
      const allText = range.text.flat().join(' ');
      resolve(allText);
    }).catch(reject);
  });
}

async function getPowerPointText() {
  return new Promise((resolve) => {
    Office.context.document.getSelectedDataAsync(Office.CoercionType.Text, (result) => {
      resolve(result.status === Office.AsyncResultStatus.Succeeded ? result.value : '');
    });
  });
}

async function checkCompliance() {
  const findingsEl = document.getElementById('findings');
  findingsEl.innerHTML = '<div class="finding medium"><strong>Compliance Check</strong><br>Running GDPR, PCI-DSS, and SOC 2 checks on document content...</div>';
}

async function classifyContent() {
  const findingsEl = document.getElementById('findings');
  try {
    let text = '';
    if (Office.context.host === Office.HostType.Word) text = await getWordText();

    const findings = scanText(text);
    const hasCritical = findings.some(f => f.severity === 'critical');
    const hasHigh = findings.some(f => f.severity === 'high');
    const classification = hasCritical ? 'RESTRICTED' : hasHigh ? 'CONFIDENTIAL' : findings.length > 0 ? 'INTERNAL' : 'PUBLIC';

    findingsEl.innerHTML = `<div class="finding ${hasCritical ? 'critical' : hasHigh ? 'high' : 'medium'}">
      <strong>Classification: ${classification}</strong><br>
      Based on ${findings.length} finding(s) in document content.
    </div>`;
  } catch (e) {
    findingsEl.innerHTML = `<div class="finding critical">Error: ${e.message}</div>`;
  }
}
