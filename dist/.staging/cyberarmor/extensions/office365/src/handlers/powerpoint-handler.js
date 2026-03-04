/**
 * AIShields Protect - PowerPoint Handler
 * DLP scanning for slides, notes, and embedded content.
 */

const DLP_PATTERNS = [
  { name: "SSN", pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Credit Card", pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, severity: "critical", classification: "RESTRICTED" },
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Private Key", pattern: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Email Address", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, severity: "medium", classification: "INTERNAL" },
  { name: "API Key Generic", pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi, severity: "high", classification: "CONFIDENTIAL" },
  { name: "Password in Text", pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{6,})['"]?/gi, severity: "high", classification: "CONFIDENTIAL" },
];

const AI_CONTENT_PATTERNS = [
  { name: "AI Disclosure", pattern: /\b(as an ai|as a language model|i don't have personal|my training data)\b/gi },
  { name: "AI Prompt Residue", pattern: /\b(system prompt|user prompt|<\|im_start\|>|<\|im_end\|>)\b/gi },
  { name: "Code Blocks", pattern: /```[\s\S]*?```/g },
];

let config = { serverUrl: "", apiKey: "", tenantId: "", enabled: true };

function init(cfg) {
  config = { ...config, ...cfg };
}

async function scan() {
  const findings = [];

  try {
    await PowerPoint.run(async (context) => {
      const presentation = context.presentation;
      const slides = presentation.slides;
      slides.load("items");
      await context.sync();

      for (let i = 0; i < slides.items.length; i++) {
        const slide = slides.items[i];
        const slideFindings = await scanSlide(context, slide, i + 1);
        findings.push(...slideFindings);
      }

      // Scan presentation properties
      try {
        const properties = presentation.properties;
        if (properties) {
          properties.load("title,subject,author,keywords,comments");
          await context.sync();
          const metaText = [
            properties.title, properties.subject, properties.author,
            properties.keywords, properties.comments,
          ].filter(Boolean).join(" ");

          for (const rule of DLP_PATTERNS) {
            if (new RegExp(rule.pattern.source, rule.pattern.flags).test(metaText)) {
              findings.push({
                type: "dlp_metadata",
                rule: rule.name,
                severity: rule.severity,
                classification: rule.classification,
                location: "presentation_properties",
                app: "PowerPoint",
              });
            }
          }
        }
      } catch (_) {
        // Properties API may not be available in all versions
      }

      const classification = classifyContent(findings);
      findings.push({
        type: "classification",
        level: classification,
        app: "PowerPoint",
        slideCount: slides.items.length,
      });
    });
  } catch (error) {
    findings.push({ type: "error", message: `PowerPoint scan error: ${error.message}`, app: "PowerPoint" });
  }

  if (config.serverUrl && findings.length > 0) {
    reportFindings(findings);
  }

  return findings;
}

async function scanSlide(context, slide, slideNumber) {
  const findings = [];

  try {
    // Scan shapes (text boxes, titles, etc.)
    const shapes = slide.shapes;
    shapes.load("items");
    await context.sync();

    for (const shape of shapes.items) {
      try {
        if (shape.textFrame) {
          const textFrame = shape.textFrame;
          textFrame.load("textRange/text,hasText");
          await context.sync();

          if (textFrame.hasText) {
            const text = textFrame.textRange.text || "";
            scanTextForFindings(text, findings, `Slide ${slideNumber}`, "shape");
          }
        }

        // Check for hyperlinks in shapes
        if (shape.hyperlink) {
          shape.load("hyperlink/address");
          await context.sync();
          if (shape.hyperlink && shape.hyperlink.address) {
            const url = shape.hyperlink.address;
            if (isSuspiciousUrl(url)) {
              findings.push({
                type: "suspicious_link",
                severity: "medium",
                slide: slideNumber,
                url: url.substring(0, 100),
                app: "PowerPoint",
              });
            }
          }
        }
      } catch (_) {
        // Skip shapes that don't support text
      }
    }

    // Scan slide notes
    try {
      const notesSlide = slide.notesSlide;
      if (notesSlide) {
        const notesBody = notesSlide.shapes;
        notesBody.load("items");
        await context.sync();

        for (const noteShape of notesBody.items) {
          try {
            if (noteShape.textFrame) {
              noteShape.textFrame.load("textRange/text,hasText");
              await context.sync();
              if (noteShape.textFrame.hasText) {
                const noteText = noteShape.textFrame.textRange.text || "";
                scanTextForFindings(noteText, findings, `Slide ${slideNumber}`, "notes");
              }
            }
          } catch (_) {
            // Skip
          }
        }
      }
    } catch (_) {
      // Notes may not exist for all slides
    }
  } catch (error) {
    findings.push({
      type: "error",
      message: `Slide ${slideNumber} scan error: ${error.message}`,
      app: "PowerPoint",
    });
  }

  return findings;
}

function scanTextForFindings(text, findings, location, subLocation) {
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
        app: "PowerPoint",
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
        app: "PowerPoint",
      });
    }
  }
}

function isSuspiciousUrl(url) {
  const suspicious = [
    /^javascript:/i,
    /^data:/i,
    /^vbscript:/i,
    /bit\.ly|tinyurl\.com|t\.co|goo\.gl/i,
    /\.(ru|cn|tk|ml|ga|cf)\//i,
  ];
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
        source: "office365-powerpoint",
        findings,
        timestamp: new Date().toISOString(),
      }),
    });
  } catch (err) {
    console.warn("AIShields: Report error:", err.message);
  }
}

export { init, scan };
