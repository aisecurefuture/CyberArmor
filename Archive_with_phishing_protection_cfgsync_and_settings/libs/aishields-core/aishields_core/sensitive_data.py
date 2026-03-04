from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Tuple


SENSITIVE_PATTERNS: list[Tuple[str, re.Pattern]] = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("phone", re.compile(r"\b\d{10}\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("zip", re.compile(r"\b\d{5}(?:-\d{4})?\b")),
    ("bank_account_or_ssn", re.compile(r"\b\d{9}\b")),
    ("credit_card", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("drivers_license", re.compile(r"\b[A-Z]{1,2}\d{4,8}\b")),
    ("drivers_license_alt", re.compile(r"\b(?:[A-Za-z]{1}\d{3})[-\d{4}]{2}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}[0-9]{2}[a-zA-Z0-9]{4}[0-9]{14}\b")),
    ("api_key", re.compile(r"(?i)\b(?:sk-|pk_)[A-Za-z0-9]{16,}")),
    ("secret", re.compile(r"(?i)secret[_-]?key")),
]


@dataclass
class SensitiveDataResult:
    findings: List[str] = field(default_factory=list)
    redacted_text: str = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


class SensitiveDataDetector:
    def __init__(self, patterns: list[tuple[str, re.Pattern]] | None = None):
        self.patterns = patterns or SENSITIVE_PATTERNS

    def detect(self, text: str) -> SensitiveDataResult:
        value = text or ""
        findings: list[str] = []
        redacted = value
        for label, pattern in self.patterns:
            matches = pattern.findall(value)
            if matches:
                findings.append(label)
                redacted = pattern.sub(f"[REDACTED-{label}]", redacted)
        return SensitiveDataResult(findings=findings, redacted_text=redacted)
