/**
 * AIShields Protect - OneNote Handler
 * DLP scanning and AI content detection for OneNote notebooks.
 */

const DLP_PATTERNS = [
  { name: "SSN", pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Credit Card", pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, severity: "critical", classification: "RESTRICTED" },
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Private Key", pattern: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Email Address", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, severity: "medium", classification: "INTERNAL" },
  { name: "API Key Generic", pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi, severity: "high", classification: "CONFIDENTIAL" },
  { name: "Password in Text", pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{6,})['"]?/gi, severity: "high", classification: "CONFIDENTIAL" },
  { name: "Bearer Token", pattern: /Bearer\s+[A-Za-z0-9_\-\.]{20,}/g, severity: "high", classification: "CONFIDENTIAL" },
];

const AI_CONTENT_PATTERNS = [
  { name: "AI Disclosure", pattern: /\b(as an ai|as a language model|i don't have personal)\b/gi },
  { name: "AI Prompt", pattern: /\b(system prompt|user prompt|assistant response)\b/gi },
  { name: "Prompt Template", pattern: /\{\{[^}]+\}\}|\{[a-z_]+\}/g },
  { name: "Code Blocks", pattern: /```[\s\S]*?```/g },
];

let config = { serverUrl: "", apiKey: "", tenantId: "", enabled: true };

function init(cfg) {
  config = { ...config, ...cfg };
}

async function scan() {
  const findings = [];

  try {
    // OneNote API is accessed differently - through REST API or page content
    await OneNote.run(async (context) => {
      const page = context.application.getActivePage();
      page.load("id,title");
      await context.sync();

      const pageTitle = page.title || "Untitled";

      // Scan page title
      scanTextForFindings(pageTitle, findings, "Page Title", "title");

      // Get page content - OneNote provides HTML content
      const pageContent = page.contents;
      pageContent.load("items");
      await context.sync();

      for (const item of pageContent.items) {
        try {
          if (item.type === "Outline") {
            const outline = item.outline;
            outline.load("paragraphs/items");
            await context.sync();

            for (const paragraph of outline.paragraphs.items) {
              try {
                const richText = paragraph.richText;
                if (richText) {
                  richText.load("text");
                  await context.sync();

                  const text = richText.text || "";
                  scanTextForFindings(text, findings, pageTitle, "paragraph");
                }
              } catch (_) {
                // Skip paragraphs without text
              }

              // Check for tables within outlines
              try {
                if (paragraph.type === "Table") {
                  const table = paragraph.table;
                  table.load("rows/items");
                  await context.sync();

                  for (const row of table.rows.items) {
                    row.load("cells/items");
                    await context.sync();

                    for (const cell of row.cells.items) {
                      cell.load("paragraphs/items");
                      await context.sync();

                      for (const cellPara of cell.paragraphs.items) {
                        try {
                          const cellText = cellPara.richText;
                          if (cellText) {
                            cellText.load("text");
                            await context.sync();
                            scanTextForFindings(cellText.text || "", findings, pageTitle, "table_cell");
                          }
                        } catch (_) {
                          // Skip
                        }
                      }
                    }
                  }
                }
              } catch (_) {
                // Tables not supported or not present
              }
            }
          }

          // Scan embedded images (check alt text / descriptions)
          if (item.type === "Image") {
            try {
              const image = item.image;
              image.load("description,hyperlink");
              await context.sync();

              if (image.description) {
                scanTextForFindings(image.description, findings, pageTitle, "image_alt");
              }
              if (image.hyperlink) {
                if (isSuspiciousUrl(image.hyperlink)) {
                  findings.push({
                    type: "suspicious_link",
                    severity: "medium",
                    page: pageTitle,
                    location: "image_hyperlink",
                    app: "OneNote",
                  });
                }
              }
            } catch (_) {
              // Image properties not available
            }
          }
        } catch (itemError) {
          // Skip content items that can't be read
        }
      }

      // Scan ink content if available (converted to text via OCR)
      try {
        const inkContent = page.inkAnalysisOrNull;
        if (inkContent) {
          inkContent.load("paragraphs/items");
          await context.sync();
          for (const inkPara of inkContent.paragraphs.items) {
            inkPara.load("recognizedText");
            await context.sync();
            if (inkPara.recognizedText) {
              scanTextForFindings(inkPara.recognizedText, findings, pageTitle, "ink_recognition");
            }
          }
        }
      } catch (_) {
        // Ink analysis not available
      }

      const classification = classifyContent(findings);
      findings.push({
        type: "classification",
        level: classification,
        app: "OneNote",
        pageTitle: pageTitle,
      });
    });
  } catch (error) {
    findings.push({ type: "error", message: `OneNote scan error: ${error.message}`, app: "OneNote" });
  }

  if (config.serverUrl && findings.length > 0) {
    reportFindings(findings);
  }

  return findings;
}

function scanTextForFindings(text, findings, location, subLocation) {
  if (!text) return;

  for (const rule of DLP_PATTERNS) {
    const matches = text.match(new RegExp(rule.pattern.source, rule.pattern.flags));
    if (matches) {
      findings.push({
        type: "dlp",
        rule: rule.name,
        count: matches.length,
        severity: rule.severity,
        classification: rule.classification,
        location: location,
        subLocation: subLocation,
        app: "OneNote",
      });
    }
  }

  for (const rule of AI_CONTENT_PATTERNS) {
    const matches = text.match(new RegExp(rule.pattern.source, rule.pattern.flags));
    if (matches) {
      findings.push({
        type: "ai_content",
        rule: rule.name,
        count: matches.length,
        severity: "medium",
        location: location,
        subLocation: subLocation,
        app: "OneNote",
      });
    }
  }
}

function isSuspiciousUrl(url) {
  const suspicious = [/^javascript:/i, /^data:/i, /bit\.ly|tinyurl/i];
  return suspicious.some((p) => p.test(url));
}

function classifyContent(findings) {
  const levels = findings.filter((f) => f.classification).map((f) => f.classification);
  if (levels.includes("RESTRICTED")) return "RESTRICTED";
  if (levels.includes("CONFIDENTIAL")) return "CONFIDENTIAL";
  if (levels.includes("INTERNAL")) return "INTERNAL";
  return "PUBLIC";
}

async function reportFindings(findings) {
  try {
    await fetch(`${config.serverUrl}/api/v1/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": config.apiKey },
      body: JSON.stringify({
        tenant_id: config.tenantId,
        source: "office365-onenote",
        findings,
        timestamp: new Date().toISOString(),
      }),
    });
  } catch (err) {
    console.warn("AIShields: Report error:", err.message);
  }
}

export { init, scan };
