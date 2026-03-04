/**
 * AIShields Protect - Outlook Handler
 * Email DLP scanning, AI-generated content detection, recipient policy,
 * phishing detection, and attachment analysis for Outlook.
 */

const DLP_PATTERNS = [
  { name: "SSN", pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Credit Card", pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, severity: "critical", classification: "RESTRICTED" },
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Private Key", pattern: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----/g, severity: "critical", classification: "RESTRICTED" },
  { name: "Email Address", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, severity: "low", classification: "INTERNAL" },
  { name: "API Key Generic", pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/gi, severity: "high", classification: "CONFIDENTIAL" },
  { name: "Password in Text", pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{6,})['"]?/gi, severity: "high", classification: "CONFIDENTIAL" },
  { name: "Bearer Token", pattern: /Bearer\s+[A-Za-z0-9_\-\.]{20,}/g, severity: "high", classification: "CONFIDENTIAL" },
  { name: "JWT Token", pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, severity: "high", classification: "CONFIDENTIAL" },
  { name: "Azure Connection String", pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+/g, severity: "critical", classification: "RESTRICTED" },
  { name: "AWS Secret Key", pattern: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: "critical", classification: "RESTRICTED" },
];

const AI_CONTENT_PATTERNS = [
  { name: "AI Disclosure", pattern: /\b(as an ai|as a language model|i don't have personal|i cannot browse the internet)\b/gi },
  { name: "AI Hedging", pattern: /\b(it'?s worth noting that|it'?s important to note|i should mention that|please note that i)\b/gi },
  { name: "AI Structure", pattern: /\b(here are (?:some|the|a few) (?:key )?(?:points|steps|considerations|recommendations))\b/gi },
  { name: "AI Prompt Residue", pattern: /\b(system prompt|user prompt|assistant response|<\|im_start\|>|<\|im_end\|>)\b/gi },
  { name: "LLM Artifacts", pattern: /```[\s\S]*?```|<thinking>[\s\S]*?<\/thinking>/g },
];

const PHISHING_PATTERNS = [
  { name: "Urgency", pattern: /\b(urgent|immediately|action required|verify your account|suspend|expire|within 24 hours)\b/gi },
  { name: "Credential Request", pattern: /\b(enter your password|verify your identity|confirm your account|update your payment|reset your credentials)\b/gi },
  { name: "Suspicious URL", pattern: /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/g },
  { name: "Homograph Attack", pattern: /https?:\/\/[^\s]*(?:xn--|[^\x00-\x7F])/g },
  { name: "URL Obfuscation", pattern: /(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|v\.gd|buff\.ly)\/[A-Za-z0-9]+/g },
];

const SUSPICIOUS_ATTACHMENT_EXTENSIONS = [
  ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
  ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".msi", ".msp",
  ".dll", ".hta", ".cpl", ".inf", ".reg", ".lnk", ".iso", ".img",
];

let config = {
  serverUrl: "",
  apiKey: "",
  tenantId: "",
  enabled: true,
  internalDomains: [],
  blockedExternalDomains: [],
  maxExternalRecipients: 10,
  blockOnCritical: false,
};

function init(cfg) {
  config = { ...config, ...cfg };
}

async function scan() {
  const findings = [];
  const item = Office.context.mailbox.item;

  if (!item) {
    findings.push({ type: "error", message: "No mail item available", app: "Outlook" });
    return findings;
  }

  try {
    // Determine if compose or read mode
    const isCompose = !!item.body?.setAsync;

    if (isCompose) {
      await scanComposeMode(item, findings);
    } else {
      await scanReadMode(item, findings);
    }

    const classification = classifyContent(findings);
    findings.push({
      type: "classification",
      level: classification,
      app: "Outlook",
      mode: isCompose ? "compose" : "read",
    });
  } catch (error) {
    findings.push({ type: "error", message: `Outlook scan error: ${error.message}`, app: "Outlook" });
  }

  if (config.serverUrl && findings.length > 0) {
    reportFindings(findings);
  }

  return findings;
}

function scanComposeMode(item, findings) {
  return new Promise((resolve) => {
    let pending = 0;
    const checkDone = () => { if (--pending <= 0) resolve(); };

    // Scan subject
    pending++;
    item.subject.getAsync((result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded && result.value) {
        scanTextForDLP(result.value, findings, "subject");
        scanForPhishing(result.value, findings, "subject");
      }
      checkDone();
    });

    // Scan body
    pending++;
    item.body.getAsync(Office.CoercionType.Text, (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded && result.value) {
        scanTextForDLP(result.value, findings, "body");
        scanForAIContent(result.value, findings, "body");
        scanForPhishing(result.value, findings, "body");
      }
      checkDone();
    });

    // Scan recipients (To)
    pending++;
    item.to.getAsync((result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded && result.value) {
        scanRecipients(result.value, findings, "to");
      }
      checkDone();
    });

    // Scan recipients (CC)
    pending++;
    item.cc.getAsync((result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded && result.value) {
        scanRecipients(result.value, findings, "cc");
      }
      checkDone();
    });

    // Scan recipients (BCC)
    pending++;
    item.bcc.getAsync((result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded && result.value) {
        scanRecipients(result.value, findings, "bcc");
      }
      checkDone();
    });

    // Scan attachments
    pending++;
    try {
      const attachments = item.attachments;
      if (attachments) {
        scanAttachments(attachments, findings);
      }
    } catch (_) {
      // Attachments not available in compose
    }
    checkDone();
  });
}

function scanReadMode(item, findings) {
  return new Promise((resolve) => {
    let pending = 0;
    const checkDone = () => { if (--pending <= 0) resolve(); };

    // Scan subject (read mode - direct property)
    if (item.subject) {
      scanTextForDLP(item.subject, findings, "subject");
      scanForPhishing(item.subject, findings, "subject");
    }

    // Scan sender
    if (item.from) {
      const senderDomain = item.from.emailAddress?.split("@")[1] || "";
      if (config.blockedExternalDomains.includes(senderDomain.toLowerCase())) {
        findings.push({
          type: "blocked_sender_domain",
          severity: "high",
          domain: senderDomain,
          sender: item.from.emailAddress,
          app: "Outlook",
        });
      }
    }

    // Scan body
    pending++;
    item.body.getAsync(Office.CoercionType.Text, (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded && result.value) {
        scanTextForDLP(result.value, findings, "body");
        scanForAIContent(result.value, findings, "body");
        scanForPhishing(result.value, findings, "body");
      }
      checkDone();
    });

    // Scan HTML body for hidden content
    pending++;
    item.body.getAsync(Office.CoercionType.Html, (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded && result.value) {
        scanHtmlForHiddenContent(result.value, findings);
      }
      checkDone();
    });

    // Scan attachments
    if (item.attachments && item.attachments.length > 0) {
      scanAttachments(item.attachments, findings);
    }

    // Scan internet headers for anomalies
    pending++;
    try {
      item.getAllInternetHeadersAsync((result) => {
        if (result.status === Office.AsyncResultStatus.Succeeded) {
          scanHeaders(result.value, findings);
        }
        checkDone();
      });
    } catch (_) {
      checkDone();
    }

    if (pending === 0) resolve();
  });
}

function scanTextForDLP(text, findings, location) {
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
        app: "Outlook",
      });
    }
  }
}

function scanForAIContent(text, findings, location) {
  if (!text) return;
  let aiScore = 0;

  for (const rule of AI_CONTENT_PATTERNS) {
    const matches = text.match(new RegExp(rule.pattern.source, rule.pattern.flags));
    if (matches) {
      aiScore += matches.length;
      findings.push({
        type: "ai_content",
        rule: rule.name,
        count: matches.length,
        severity: "medium",
        location: location,
        snippets: matches.slice(0, 3),
        app: "Outlook",
      });
    }
  }

  // Aggregate AI score
  if (aiScore >= 3) {
    findings.push({
      type: "ai_content_high_confidence",
      severity: "high",
      score: aiScore,
      location: location,
      message: "Email body has high AI-generated content indicators",
      app: "Outlook",
    });
  }
}

function scanForPhishing(text, findings, location) {
  if (!text) return;
  for (const rule of PHISHING_PATTERNS) {
    const matches = text.match(new RegExp(rule.pattern.source, rule.pattern.flags));
    if (matches) {
      findings.push({
        type: "phishing_indicator",
        rule: rule.name,
        count: matches.length,
        severity: "high",
        location: location,
        snippets: matches.slice(0, 3),
        app: "Outlook",
      });
    }
  }
}

function scanRecipients(recipients, findings, field) {
  if (!recipients || !recipients.length) return;

  const externalRecipients = [];
  for (const recipient of recipients) {
    const email = recipient.emailAddress || "";
    const domain = email.split("@")[1]?.toLowerCase() || "";

    // Check external domain policy
    if (config.internalDomains.length > 0 && !config.internalDomains.includes(domain)) {
      externalRecipients.push(email);
    }

    // Check blocked domains
    if (config.blockedExternalDomains.includes(domain)) {
      findings.push({
        type: "blocked_recipient_domain",
        severity: "high",
        email: email,
        domain: domain,
        field: field,
        app: "Outlook",
      });
    }
  }

  // Check external recipient count
  if (externalRecipients.length > config.maxExternalRecipients) {
    findings.push({
      type: "excessive_external_recipients",
      severity: "high",
      count: externalRecipients.length,
      limit: config.maxExternalRecipients,
      field: field,
      app: "Outlook",
    });
  }

  if (externalRecipients.length > 0) {
    findings.push({
      type: "external_recipients",
      severity: "low",
      count: externalRecipients.length,
      domains: [...new Set(externalRecipients.map((e) => e.split("@")[1]))],
      field: field,
      app: "Outlook",
    });
  }
}

function scanAttachments(attachments, findings) {
  const items = Array.isArray(attachments) ? attachments : (attachments.items || []);

  for (const attachment of items) {
    const name = (attachment.name || attachment.fileName || "").toLowerCase();
    const size = attachment.size || 0;

    // Check for suspicious extensions
    for (const ext of SUSPICIOUS_ATTACHMENT_EXTENSIONS) {
      if (name.endsWith(ext)) {
        findings.push({
          type: "suspicious_attachment",
          severity: "critical",
          filename: name,
          extension: ext,
          size: size,
          app: "Outlook",
        });
        break;
      }
    }

    // Check for double extensions (e.g., document.pdf.exe)
    const parts = name.split(".");
    if (parts.length > 2) {
      const lastExt = "." + parts[parts.length - 1];
      if (SUSPICIOUS_ATTACHMENT_EXTENSIONS.includes(lastExt)) {
        findings.push({
          type: "double_extension_attachment",
          severity: "critical",
          filename: name,
          app: "Outlook",
        });
      }
    }

    // Check for password-protected archives (common malware delivery)
    if (name.match(/\.(zip|7z|rar)$/)) {
      findings.push({
        type: "archive_attachment",
        severity: "medium",
        filename: name,
        size: size,
        message: "Archive attachment detected - may contain hidden threats",
        app: "Outlook",
      });
    }

    // Scan attachment name for DLP
    for (const rule of DLP_PATTERNS) {
      if (new RegExp(rule.pattern.source, rule.pattern.flags).test(name)) {
        findings.push({
          type: "dlp_attachment_name",
          rule: rule.name,
          severity: rule.severity,
          classification: rule.classification,
          filename: name,
          app: "Outlook",
        });
      }
    }

    // Large attachment warning
    if (size > 25 * 1024 * 1024) {
      findings.push({
        type: "large_attachment",
        severity: "low",
        filename: name,
        sizeMB: Math.round(size / 1024 / 1024),
        app: "Outlook",
      });
    }
  }
}

function scanHtmlForHiddenContent(html, findings) {
  if (!html) return;

  // Detect hidden text (potential phishing / social engineering)
  const hiddenPatterns = [
    { name: "Display None", pattern: /display\s*:\s*none/gi },
    { name: "Zero Font Size", pattern: /font-size\s*:\s*0/gi },
    { name: "White on White", pattern: /color\s*:\s*(?:#fff(?:fff)?|white|rgb\(255\s*,\s*255\s*,\s*255\))/gi },
    { name: "Hidden Overflow", pattern: /overflow\s*:\s*hidden.*height\s*:\s*0/gi },
    { name: "Tiny Text", pattern: /font-size\s*:\s*[01]px/gi },
  ];

  for (const rule of hiddenPatterns) {
    if (rule.pattern.test(html)) {
      findings.push({
        type: "hidden_content",
        rule: rule.name,
        severity: "high",
        location: "html_body",
        message: `Email contains hidden content (${rule.name})`,
        app: "Outlook",
      });
    }
  }

  // Detect tracking pixels
  const trackingPixelPattern = /<img[^>]*(?:width|height)\s*=\s*["']?[01]["']?[^>]*(?:width|height)\s*=\s*["']?[01]["']?/gi;
  if (trackingPixelPattern.test(html)) {
    findings.push({
      type: "tracking_pixel",
      severity: "low",
      location: "html_body",
      app: "Outlook",
    });
  }

  // Detect forms in email
  if (/<form[\s>]/i.test(html)) {
    findings.push({
      type: "embedded_form",
      severity: "high",
      location: "html_body",
      message: "Email contains an embedded form - potential phishing",
      app: "Outlook",
    });
  }
}

function scanHeaders(headers, findings) {
  if (!headers) return;

  // Check for SPF/DKIM/DMARC failures
  const authHeader = headers["Authentication-Results"] || headers["authentication-results"] || "";
  if (authHeader) {
    if (/spf=fail/i.test(authHeader)) {
      findings.push({ type: "spf_fail", severity: "high", app: "Outlook" });
    }
    if (/dkim=fail/i.test(authHeader)) {
      findings.push({ type: "dkim_fail", severity: "high", app: "Outlook" });
    }
    if (/dmarc=fail/i.test(authHeader)) {
      findings.push({ type: "dmarc_fail", severity: "critical", app: "Outlook" });
    }
  }

  // Check for reply-to mismatch (common phishing technique)
  const from = headers["From"] || headers["from"] || "";
  const replyTo = headers["Reply-To"] || headers["reply-to"] || "";
  if (replyTo && from) {
    const fromDomain = from.match(/@([^>]+)/)?.[1] || "";
    const replyDomain = replyTo.match(/@([^>]+)/)?.[1] || "";
    if (fromDomain && replyDomain && fromDomain.toLowerCase() !== replyDomain.toLowerCase()) {
      findings.push({
        type: "reply_to_mismatch",
        severity: "high",
        fromDomain: fromDomain,
        replyToDomain: replyDomain,
        message: "Reply-To domain differs from From domain",
        app: "Outlook",
      });
    }
  }
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
        source: "office365-outlook",
        findings,
        timestamp: new Date().toISOString(),
      }),
    });
  } catch (err) {
    console.warn("AIShields: Report error:", err.message);
  }
}

// Compose mode: scan before send (can be hooked to ItemSend event)
async function onSendValidation() {
  const findings = await scan();
  const critical = findings.filter((f) => f.severity === "critical");

  if (critical.length > 0 && config.blockOnCritical) {
    return {
      allowed: false,
      reason: `Blocked: ${critical.length} critical finding(s) detected - ${critical.map((f) => f.rule || f.type).join(", ")}`,
      findings: critical,
    };
  }

  return { allowed: true, findings };
}

export { init, scan, onSendValidation };
