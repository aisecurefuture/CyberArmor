/**
 * AIShields Protect - Excel Handler
 * DLP scanning, formula injection detection, and data classification for Excel.
 */

const DLP_PATTERNS = [
  { name: "SSN", pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Credit Card", pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, severity: "critical", classification: "RESTRICTED" },
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Private Key", pattern: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Email Address", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, severity: "medium", classification: "INTERNAL" },
  { name: "API Key Generic", pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi, severity: "high", classification: "CONFIDENTIAL" },
  { name: "Azure Connection String", pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+/g, severity: "critical", classification: "RESTRICTED" },
];

// Formula injection patterns (CSV injection / formula injection attacks)
const FORMULA_INJECTION_PATTERNS = [
  { name: "Command Execution", pattern: /^[=+\-@]\s*(?:CMD|SYSTEM|EXEC|SHELL|CALL)\s*\(/i, severity: "critical" },
  { name: "DDE Attack", pattern: /^[=+\-@]\s*(?:DDE|cmd\|')\s*\(/i, severity: "critical" },
  { name: "HYPERLINK Injection", pattern: /^=\s*HYPERLINK\s*\(\s*"(?:https?|ftp|file|javascript):/i, severity: "high" },
  { name: "External Data", pattern: /^=\s*(?:WEBSERVICE|FILTERXML|ENCODEURL)\s*\(/i, severity: "high" },
  { name: "PowerQuery Injection", pattern: /^=\s*(?:LET|LAMBDA)\s*\(.*(?:Web\.Contents|File\.Contents)/i, severity: "critical" },
  { name: "Macro Trigger", pattern: /^=\s*(?:EXEC|RUN|CALL)\s*\(/i, severity: "critical" },
  { name: "Information Disclosure", pattern: /^=\s*(?:INFO|CELL|GET\.WORKBOOK|DOCUMENTS)\s*\(/i, severity: "medium" },
];

let config = {
  serverUrl: "",
  apiKey: "",
  tenantId: "",
  enabled: true,
  maxCellsToScan: 50000,
};

function init(cfg) {
  config = { ...config, ...cfg };
}

async function scan() {
  const findings = [];

  try {
    await Excel.run(async (context) => {
      const sheets = context.workbook.worksheets;
      sheets.load("items/name");
      await context.sync();

      for (const sheet of sheets.items) {
        const sheetFindings = await scanSheet(context, sheet);
        findings.push(...sheetFindings);
      }

      // Scan workbook properties
      const properties = context.workbook.properties;
      properties.load("title,subject,author,keywords,comments,category");
      await context.sync();

      const metaText = [
        properties.title, properties.subject, properties.author,
        properties.keywords, properties.comments, properties.category,
      ].filter(Boolean).join(" ");

      for (const rule of DLP_PATTERNS) {
        const matches = metaText.match(rule.pattern);
        if (matches) {
          findings.push({
            type: "dlp_metadata",
            rule: rule.name,
            count: matches.length,
            severity: rule.severity,
            classification: rule.classification,
            location: "workbook_properties",
            app: "Excel",
          });
        }
      }

      // Scan named ranges
      const names = context.workbook.names;
      names.load("items/name,items/value");
      await context.sync();

      for (const namedRange of names.items) {
        for (const rule of DLP_PATTERNS) {
          if (namedRange.value && rule.pattern.test(namedRange.value)) {
            findings.push({
              type: "dlp_named_range",
              rule: rule.name,
              severity: rule.severity,
              classification: rule.classification,
              rangeName: namedRange.name,
              app: "Excel",
            });
          }
        }
      }

      const classification = classifyContent(findings);
      findings.push({
        type: "classification",
        level: classification,
        app: "Excel",
        sheetCount: sheets.items.length,
      });
    });
  } catch (error) {
    findings.push({ type: "error", message: `Excel scan error: ${error.message}`, app: "Excel" });
  }

  if (config.serverUrl && findings.length > 0) {
    reportFindings(findings);
  }

  return findings;
}

async function scanSheet(context, sheet) {
  const findings = [];

  try {
    const usedRange = sheet.getUsedRangeOrNullObject();
    usedRange.load("values,formulas,address,rowCount,columnCount");
    await context.sync();

    if (usedRange.isNullObject) return findings;

    const totalCells = usedRange.rowCount * usedRange.columnCount;
    if (totalCells > config.maxCellsToScan) {
      findings.push({
        type: "warning",
        message: `Sheet "${sheet.name}" has ${totalCells} cells, scanning first ${config.maxCellsToScan}`,
        app: "Excel",
      });
    }

    const values = usedRange.values;
    const formulas = usedRange.formulas;

    let cellsScanned = 0;
    for (let row = 0; row < values.length && cellsScanned < config.maxCellsToScan; row++) {
      for (let col = 0; col < values[row].length && cellsScanned < config.maxCellsToScan; col++) {
        cellsScanned++;
        const cellValue = String(values[row][col] || "");
        const cellFormula = String(formulas[row][col] || "");
        const cellRef = getCellRef(row, col);

        // DLP scan on cell values
        for (const rule of DLP_PATTERNS) {
          const cloned = new RegExp(rule.pattern.source, rule.pattern.flags);
          if (cloned.test(cellValue)) {
            findings.push({
              type: "dlp",
              rule: rule.name,
              severity: rule.severity,
              classification: rule.classification,
              sheet: sheet.name,
              cell: cellRef,
              app: "Excel",
            });
          }
        }

        // Formula injection detection
        for (const rule of FORMULA_INJECTION_PATTERNS) {
          if (rule.pattern.test(cellFormula) || rule.pattern.test(cellValue)) {
            findings.push({
              type: "formula_injection",
              rule: rule.name,
              severity: rule.severity,
              sheet: sheet.name,
              cell: cellRef,
              formula: cellFormula.substring(0, 100),
              app: "Excel",
            });
          }
        }
      }
    }

    // Check for external links in formulas
    const externalLinkPattern = /\[([^\]]+)\]/g;
    for (let row = 0; row < formulas.length; row++) {
      for (let col = 0; col < formulas[row].length; col++) {
        const formula = String(formulas[row][col] || "");
        if (externalLinkPattern.test(formula)) {
          findings.push({
            type: "external_link",
            severity: "medium",
            sheet: sheet.name,
            cell: getCellRef(row, col),
            formula: formula.substring(0, 100),
            app: "Excel",
          });
        }
      }
    }
  } catch (error) {
    findings.push({
      type: "error",
      message: `Sheet "${sheet.name}" scan error: ${error.message}`,
      app: "Excel",
    });
  }

  return findings;
}

function getCellRef(row, col) {
  let colStr = "";
  let c = col;
  while (c >= 0) {
    colStr = String.fromCharCode(65 + (c % 26)) + colStr;
    c = Math.floor(c / 26) - 1;
  }
  return `${colStr}${row + 1}`;
}

function classifyContent(findings) {
  const severities = findings.filter((f) => f.classification).map((f) => f.classification);
  if (severities.includes("RESTRICTED")) return "RESTRICTED";
  if (severities.includes("CONFIDENTIAL")) return "CONFIDENTIAL";
  if (severities.includes("INTERNAL")) return "INTERNAL";
  return "PUBLIC";
}

async function reportFindings(findings) {
  try {
    await fetch(`${config.serverUrl}/api/v1/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": config.apiKey },
      body: JSON.stringify({
        tenant_id: config.tenantId,
        source: "office365-excel",
        findings,
        timestamp: new Date().toISOString(),
      }),
    });
  } catch (err) {
    console.warn("AIShields: Report error:", err.message);
  }
}

async function scanSelection() {
  const findings = [];
  try {
    await Excel.run(async (context) => {
      const range = context.workbook.getSelectedRange();
      range.load("values,formulas,address");
      await context.sync();

      for (let row = 0; row < range.values.length; row++) {
        for (let col = 0; col < range.values[row].length; col++) {
          const val = String(range.values[row][col] || "");
          for (const rule of DLP_PATTERNS) {
            if (new RegExp(rule.pattern.source, rule.pattern.flags).test(val)) {
              findings.push({
                type: "dlp_selection",
                rule: rule.name,
                severity: rule.severity,
                classification: rule.classification,
                address: range.address,
                app: "Excel",
              });
            }
          }
        }
      }
    });
  } catch (error) {
    findings.push({ type: "error", message: error.message, app: "Excel" });
  }
  return findings;
}

export { init, scan, scanSelection };
