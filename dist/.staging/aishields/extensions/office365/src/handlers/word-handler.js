/**
 * AIShields Protect - Word Handler
 * DLP scanning, AI content detection, and policy enforcement for Microsoft Word.
 */

const DLP_PATTERNS = [
  { name: "SSN", pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Credit Card", pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, severity: "critical", classification: "RESTRICTED" },
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Private Key", pattern: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Email Address", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, severity: "medium", classification: "INTERNAL" },
  { name: "Phone Number", pattern: /\b(\+1[-.\s]?)?(\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g, severity: "medium", classification: "INTERNAL" },
  { name: "API Key Generic", pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi, severity: "high", classification: "CONFIDENTIAL" },
  { name: "JWT Token", pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, severity: "high", classification: "CONFIDENTIAL" },
  { name: "Azure Connection String", pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+/g, severity: "critical", classification: "RESTRICTED" },
];

const AI_CONTENT_PATTERNS = [
  { name: "AI Disclosure", pattern: /\b(as an ai|as a language model|i don't have personal|i cannot browse|my training data)\b/gi },
  { name: "AI Hedging", pattern: /\b(it's worth noting that|it's important to note|I should mention)\b/gi },
  { name: "AI Prompt Residue", pattern: /\b(system prompt|user prompt|assistant response|<\|im_start\|>|<\|im_end\|>)\b/gi },
  { name: "LLM Artifacts", pattern: /```[\s\S]*?```|<thinking>[\s\S]*?<\/thinking>/g },
];

let config = {
  serverUrl: "",
  apiKey: "",
  tenantId: "",
  enabled: true,
  autoScan: true,
  blockOnCritical: false,
};

function init(cfg) {
  config = { ...config, ...cfg };
}

async function scan() {
  const findings = [];

  try {
    await Word.run(async (context) => {
      const body = context.document.body;
      body.load("text");

      const paragraphs = context.document.body.paragraphs;
      paragraphs.load("items");

      const comments = context.document.body.getComments ? null : null;

      const headers = context.document.sections.getFirst().getHeader("Primary");
      headers.load("text");

      const footers = context.document.sections.getFirst().getFooter("Primary");
      footers.load("text");

      const properties = context.document.properties;
      properties.load("title,subject,author,keywords,comments,category");

      await context.sync();

      const bodyText = body.text || "";
      const headerText = headers.text || "";
      const footerText = footers.text || "";
      const fullText = [bodyText, headerText, footerText].join("\n");

      // DLP Scanning
      for (const rule of DLP_PATTERNS) {
        const matches = fullText.match(rule.pattern);
        if (matches) {
          findings.push({
            type: "dlp",
            rule: rule.name,
            count: matches.length,
            severity: rule.severity,
            classification: rule.classification,
            locations: getMatchLocations(bodyText, rule.pattern),
            app: "Word",
          });
        }
      }

      // AI Content Detection
      for (const rule of AI_CONTENT_PATTERNS) {
        const matches = fullText.match(rule.pattern);
        if (matches) {
          findings.push({
            type: "ai_content",
            rule: rule.name,
            count: matches.length,
            severity: "medium",
            snippets: matches.slice(0, 3),
            app: "Word",
          });
        }
      }

      // Document metadata scanning
      const metaText = [
        properties.title,
        properties.subject,
        properties.author,
        properties.keywords,
        properties.comments,
        properties.category,
      ]
        .filter(Boolean)
        .join(" ");

      for (const rule of DLP_PATTERNS) {
        const matches = metaText.match(rule.pattern);
        if (matches) {
          findings.push({
            type: "dlp_metadata",
            rule: rule.name,
            count: matches.length,
            severity: rule.severity,
            classification: rule.classification,
            location: "document_properties",
            app: "Word",
          });
        }
      }

      // Track/revision scanning (check for sensitive data in tracked changes)
      const trackedChanges = context.document.body.getTrackedChanges
        ? context.document.body.getTrackedChanges()
        : null;
      if (trackedChanges) {
        trackedChanges.load("items");
        await context.sync();
        for (const change of trackedChanges.items) {
          change.load("text,type,author");
          await context.sync();
          for (const rule of DLP_PATTERNS) {
            if (change.text && rule.pattern.test(change.text)) {
              findings.push({
                type: "dlp_tracked_change",
                rule: rule.name,
                severity: rule.severity,
                classification: rule.classification,
                author: change.author,
                app: "Word",
              });
            }
          }
        }
      }

      // Content classification
      const classification = classifyContent(findings);
      findings.push({
        type: "classification",
        level: classification,
        app: "Word",
        documentTitle: properties.title || "Untitled",
      });
    });
  } catch (error) {
    findings.push({
      type: "error",
      message: `Word scan error: ${error.message}`,
      app: "Word",
    });
  }

  if (config.serverUrl && findings.length > 0) {
    reportFindings(findings);
  }

  return findings;
}

function getMatchLocations(text, pattern) {
  const locations = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const cloned = new RegExp(pattern.source, pattern.flags);
    if (cloned.test(lines[i])) {
      locations.push({
        line: i + 1,
        preview: lines[i].substring(0, 80) + (lines[i].length > 80 ? "..." : ""),
      });
    }
  }
  return locations.slice(0, 10);
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
    const response = await fetch(`${config.serverUrl}/api/v1/telemetry`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": config.apiKey,
      },
      body: JSON.stringify({
        tenant_id: config.tenantId,
        source: "office365-word",
        findings: findings,
        timestamp: new Date().toISOString(),
      }),
    });
    if (!response.ok) {
      console.warn("AIShields: Failed to report findings:", response.status);
    }
  } catch (err) {
    console.warn("AIShields: Report error:", err.message);
  }
}

async function scanSelection() {
  const findings = [];
  try {
    await Word.run(async (context) => {
      const selection = context.document.getSelection();
      selection.load("text");
      await context.sync();

      const text = selection.text || "";
      for (const rule of DLP_PATTERNS) {
        const matches = text.match(rule.pattern);
        if (matches) {
          findings.push({
            type: "dlp_selection",
            rule: rule.name,
            count: matches.length,
            severity: rule.severity,
            classification: rule.classification,
            app: "Word",
          });
        }
      }
    });
  } catch (error) {
    findings.push({ type: "error", message: error.message, app: "Word" });
  }
  return findings;
}

async function insertWatermark() {
  try {
    await Word.run(async (context) => {
      const header = context.document.sections.getFirst().getHeader("Primary");
      header.insertText(
        `[AIShields Protected | Scanned: ${new Date().toISOString()} | Classification: PENDING]`,
        Word.InsertLocation.start
      );
      await context.sync();
    });
  } catch (error) {
    console.error("AIShields: Watermark error:", error.message);
  }
}

// Register event handler for document changes (auto-scan on save)
function registerAutoScan() {
  if (!config.autoScan) return;
  try {
    Office.context.document.addHandlerAsync(
      Office.EventType.DocumentSelectionChanged,
      debounce(() => scanSelection(), 5000)
    );
  } catch (_) {
    // Event not supported in this host
  }
}

function debounce(fn, delay) {
  let timer;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

export { init, scan, scanSelection, insertWatermark, registerAutoScan };
