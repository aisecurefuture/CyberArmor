"""
DLPScanner — Data Loss Prevention scanner for AI prompts and responses.

Detects and optionally redacts sensitive data including PII, credentials,
secrets, financial data, and healthcare information.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

@dataclass
class DLPPattern:
    label: str
    pattern: re.Pattern
    placeholder: str
    severity: str = "high"     # high | medium | low
    category: str = "pii"      # pii | credential | financial | healthcare | network


_PATTERNS: List[DLPPattern] = [
    # ---- PII ----
    DLPPattern(
        label="SSN",
        pattern=re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        placeholder="[REDACTED-SSN]",
        severity="high", category="pii",
    ),
    DLPPattern(
        label="EMAIL",
        pattern=re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        placeholder="[REDACTED-EMAIL]",
        severity="medium", category="pii",
    ),
    DLPPattern(
        label="PHONE_US",
        pattern=re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        placeholder="[REDACTED-PHONE]",
        severity="medium", category="pii",
    ),
    DLPPattern(
        label="DATE_OF_BIRTH",
        pattern=re.compile(
            r"\b(?:dob|date[_\s]of[_\s]birth|born)\s*[:=]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
            re.IGNORECASE,
        ),
        placeholder="[REDACTED-DOB]",
        severity="high", category="pii",
    ),
    DLPPattern(
        label="PASSPORT",
        pattern=re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
        placeholder="[REDACTED-PASSPORT]",
        severity="high", category="pii",
    ),
    DLPPattern(
        label="DRIVERS_LICENSE",
        pattern=re.compile(
            r"\b(?:dl|driver[\'s]*\s+licen[sc]e|license\s+#?)\s*[:=]?\s*[A-Z0-9]{6,12}\b",
            re.IGNORECASE,
        ),
        placeholder="[REDACTED-DL]",
        severity="high", category="pii",
    ),
    DLPPattern(
        label="FULL_NAME_WITH_TITLE",
        pattern=re.compile(
            r"\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b"
        ),
        placeholder="[REDACTED-NAME]",
        severity="low", category="pii",
    ),

    # ---- Financial ----
    DLPPattern(
        label="CREDIT_CARD",
        pattern=re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}"
            r"|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}"
            r"|(?:2131|1800|35\d{3})\d{11})\b"
        ),
        placeholder="[REDACTED-CARD]",
        severity="high", category="financial",
    ),
    DLPPattern(
        label="BANK_ACCOUNT_US",
        pattern=re.compile(
            r"\b(?:account\s*(?:number|no|#)?)\s*[:=]?\s*(\d{8,17})\b",
            re.IGNORECASE,
        ),
        placeholder="[REDACTED-BANK-ACCOUNT]",
        severity="high", category="financial",
    ),
    DLPPattern(
        label="ROUTING_NUMBER",
        pattern=re.compile(
            r"\b(?:routing\s*(?:number|no|#)?)\s*[:=]?\s*([0-9]{9})\b",
            re.IGNORECASE,
        ),
        placeholder="[REDACTED-ROUTING]",
        severity="high", category="financial",
    ),
    DLPPattern(
        label="IBAN",
        pattern=re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b"),
        placeholder="[REDACTED-IBAN]",
        severity="high", category="financial",
    ),

    # ---- Credentials ----
    DLPPattern(
        label="AWS_ACCESS_KEY",
        pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        placeholder="[REDACTED-AWS-KEY]",
        severity="high", category="credential",
    ),
    DLPPattern(
        label="AWS_SECRET_KEY",
        pattern=re.compile(
            r"(?:aws[_\-]?secret|secret[_\-]?access[_\-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?",
            re.IGNORECASE,
        ),
        placeholder="[REDACTED-AWS-SECRET]",
        severity="high", category="credential",
    ),
    DLPPattern(
        label="GCP_API_KEY",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        placeholder="[REDACTED-GCP-KEY]",
        severity="high", category="credential",
    ),
    DLPPattern(
        label="GITHUB_TOKEN",
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"),
        placeholder="[REDACTED-GITHUB-TOKEN]",
        severity="high", category="credential",
    ),
    DLPPattern(
        label="OPENAI_API_KEY",
        pattern=re.compile(r"\bsk-[A-Za-z0-9]{48}\b"),
        placeholder="[REDACTED-OPENAI-KEY]",
        severity="high", category="credential",
    ),
    DLPPattern(
        label="ANTHROPIC_API_KEY",
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{90,110}\b"),
        placeholder="[REDACTED-ANTHROPIC-KEY]",
        severity="high", category="credential",
    ),
    DLPPattern(
        label="GENERIC_API_KEY",
        pattern=re.compile(
            r"\b(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
            re.IGNORECASE,
        ),
        placeholder="[REDACTED-APIKEY]",
        severity="high", category="credential",
    ),
    DLPPattern(
        label="BEARER_TOKEN",
        pattern=re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b", re.IGNORECASE),
        placeholder="[REDACTED-BEARER]",
        severity="high", category="credential",
    ),
    DLPPattern(
        label="PRIVATE_KEY_BLOCK",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        placeholder="[REDACTED-PRIVATE-KEY]",
        severity="high", category="credential",
    ),
    DLPPattern(
        label="PASSWORD_FIELD",
        pattern=re.compile(
            r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?",
            re.IGNORECASE,
        ),
        placeholder="[REDACTED-PASSWORD]",
        severity="high", category="credential",
    ),
    DLPPattern(
        label="SLACK_TOKEN",
        pattern=re.compile(r"\bxox[bpoa]-[0-9A-Za-z\-]{10,}\b"),
        placeholder="[REDACTED-SLACK-TOKEN]",
        severity="high", category="credential",
    ),
    DLPPattern(
        label="STRIPE_KEY",
        pattern=re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        placeholder="[REDACTED-STRIPE-KEY]",
        severity="high", category="credential",
    ),
    DLPPattern(
        label="TWILIO_SID",
        pattern=re.compile(r"\bAC[0-9a-f]{32}\b"),
        placeholder="[REDACTED-TWILIO-SID]",
        severity="high", category="credential",
    ),

    # ---- Network ----
    DLPPattern(
        label="IPV4_PRIVATE",
        pattern=re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        placeholder="[REDACTED-PRIVATE-IP]",
        severity="medium", category="network",
    ),
    DLPPattern(
        label="MAC_ADDRESS",
        pattern=re.compile(r"\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"),
        placeholder="[REDACTED-MAC]",
        severity="low", category="network",
    ),

    # ---- Healthcare ----
    DLPPattern(
        label="NPI_NUMBER",
        pattern=re.compile(r"\b(?:NPI)\s*[:=]?\s*\d{10}\b", re.IGNORECASE),
        placeholder="[REDACTED-NPI]",
        severity="high", category="healthcare",
    ),
    DLPPattern(
        label="DEA_NUMBER",
        pattern=re.compile(r"\b(?:DEA)\s*[:=]?\s*[A-Z]{2}\d{7}\b", re.IGNORECASE),
        placeholder="[REDACTED-DEA]",
        severity="high", category="healthcare",
    ),
    DLPPattern(
        label="ICD_CODE",
        pattern=re.compile(r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b"),
        placeholder="[REDACTED-ICD]",
        severity="low", category="healthcare",
    ),
]


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class DLPFinding:
    """A single DLP match found in text."""
    label: str
    category: str
    severity: str
    count: int
    positions: List[Tuple[int, int]] = field(default_factory=list)
    # Sample of matched text (first match, truncated)
    sample: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "category": self.category,
            "severity": self.severity,
            "count": self.count,
            "positions": self.positions,
            "sample": self.sample,
        }


# ---------------------------------------------------------------------------
# DLPScanner
# ---------------------------------------------------------------------------

class DLPScanner:
    """
    In-process DLP scanner.

    Usage
    -----
    scanner = DLPScanner()
    findings = scanner.scan("My SSN is 123-45-6789 and card is 4111111111111111")
    redacted = scanner.redact("Bearer sk-abc123...")
    text, findings = scanner.scan_and_redact("email: user@example.com")
    """

    def __init__(
        self,
        patterns: Optional[List[DLPPattern]] = None,
        enabled_categories: Optional[List[str]] = None,
        disabled_labels: Optional[List[str]] = None,
    ) -> None:
        """
        Parameters
        ----------
        patterns : list of DLPPattern, optional
            Override the default pattern registry.
        enabled_categories : list of str, optional
            Only scan for patterns in these categories.
            If None, all categories are enabled.
        disabled_labels : list of str, optional
            Pattern labels to disable (e.g. ["ICD_CODE"]).
        """
        source = patterns or _PATTERNS
        disabled = set(disabled_labels or [])

        if enabled_categories:
            enabled_cats = set(enabled_categories)
            self._patterns = [
                p for p in source
                if p.category in enabled_cats and p.label not in disabled
            ]
        else:
            self._patterns = [p for p in source if p.label not in disabled]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, text: str) -> List[DLPFinding]:
        """
        Scan *text* for all registered sensitive patterns.

        Returns a list of DLPFinding objects (may be empty).
        """
        if not text:
            return []

        findings: List[DLPFinding] = []
        for p in self._patterns:
            matches = list(p.pattern.finditer(text))
            if not matches:
                continue
            positions = [(m.start(), m.end()) for m in matches]
            sample_match = matches[0].group(0)
            sample = (sample_match[:20] + "…") if len(sample_match) > 20 else sample_match
            findings.append(
                DLPFinding(
                    label=p.label,
                    category=p.category,
                    severity=p.severity,
                    count=len(matches),
                    positions=positions,
                    sample=sample,
                )
            )
        return findings

    def redact(self, text: str) -> str:
        """
        Return *text* with all detected sensitive patterns replaced by
        their respective placeholders.
        """
        if not text:
            return text
        result = text
        for p in self._patterns:
            result = p.pattern.sub(p.placeholder, result)
        return result

    def scan_and_redact(self, text: str) -> Tuple[str, List[DLPFinding]]:
        """
        Scan *text*, then return the redacted version along with findings.

        Returns
        -------
        redacted_text : str
        findings : list of DLPFinding
        """
        findings = self.scan(text)
        redacted = self.redact(text) if findings else text
        return redacted, findings

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def has_sensitive_data(self, text: str) -> bool:
        """Quick boolean check — returns True if any sensitive data is found."""
        if not text:
            return False
        for p in self._patterns:
            if p.pattern.search(text):
                return True
        return False

    def scan_fields(self, fields: Dict[str, str]) -> Dict[str, List[DLPFinding]]:
        """
        Scan multiple named fields at once.

        Returns a dict mapping field_name -> list of findings.
        Only fields with findings are included.
        """
        results: Dict[str, List[DLPFinding]] = {}
        for name, value in fields.items():
            found = self.scan(value or "")
            if found:
                results[name] = found
        return results

    def redact_fields(self, fields: Dict[str, str]) -> Dict[str, str]:
        """
        Redact all fields in a dict, returning a new dict with redacted values.
        """
        return {name: self.redact(value or "") for name, value in fields.items()}

    def summary(self, findings: List[DLPFinding]) -> Dict[str, Any]:
        """
        Produce a human-readable summary of findings.
        """
        if not findings:
            return {"total_findings": 0, "categories": {}, "highest_severity": None}

        categories: Dict[str, int] = {}
        severity_order = {"high": 3, "medium": 2, "low": 1}
        highest = "low"

        for f in findings:
            categories[f.category] = categories.get(f.category, 0) + f.count
            if severity_order.get(f.severity, 0) > severity_order.get(highest, 0):
                highest = f.severity

        return {
            "total_findings": sum(f.count for f in findings),
            "unique_labels": [f.label for f in findings],
            "categories": categories,
            "highest_severity": highest,
        }

    def __repr__(self) -> str:
        return f"DLPScanner(patterns={len(self._patterns)})"
