# AiShields Browser Protection – usage string for store listing or docs
# This keeps a single source of truth for what the extension does and why it
# requests its permissions.

use_string <- paste(
  "AiShields Browser Protection flags possible PII/CUI as you type and before form submission.",
  "It scans text fields and contenteditable areas for SSNs, phone numbers, emails, credit cards, IBANs, and other identifiers.",
  "If sensitive data is detected, the extension warns the user and can redact values in outgoing requests.",
  "Permissions: scripting, activeTab, tabs, storage, declarativeNetRequest, and declarativeNetRequestFeedback.",
  "Host access: http://*/* and https://*/* to allow form scanning and request inspection on visited sites.",
  "Network: optional POST to https://127.0.0.1:8078/siem/event to record security events when configured.",
  sep = "\n"
)
