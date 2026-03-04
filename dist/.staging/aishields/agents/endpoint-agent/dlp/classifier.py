"""Data Classification Engine with Custom Label Override Support.

Classifies content into sensitivity levels: public, internal, confidential,
restricted, top_secret. Supports tenant-admin custom labels and manual overrides.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class ClassificationResult:
    level: str  # public, internal, confidential, restricted, top_secret
    labels: List[str] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    confidence: float = 0.0
    source: str = "auto"  # auto, custom_label, manual_override
    custom_label: Optional[str] = None


# Built-in PII/PHI/PCI detection patterns
SENSITIVITY_PATTERNS = {
    "top_secret": [
        (r"\b(?:TOP\s+SECRET|TS//SCI|CLASSIFIED)\b", "classification_marker"),
    ],
    "restricted": [
        (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
        (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "credit_card"),
        (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key"),
        (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "private_key"),
        (r"\b(?:sk-|pk_live_)[A-Za-z0-9]{20,}\b", "api_secret_key"),
    ],
    "confidential": [
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "email"),
        (r"\b\d{9}\b", "bank_account_or_ssn"),
        (r"\b[A-Z]{2}\d{2}[A-Za-z0-9]{4}\d{14}\b", "iban"),
        (r"(?i)password\s*[:=]\s*\S+", "password_in_text"),
        (r"(?i)secret[_-]?key\s*[:=]\s*\S+", "secret_key"),
        (r"\b(?:DOB|Date\s+of\s+Birth)\s*[:=]\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", "date_of_birth"),
    ],
    "internal": [
        (r"\b\d{10}\b", "phone_number"),
        (r"\b\d{5}(?:-\d{4})?\b", "zip_code"),
        (r"\b[A-Z]{1,2}\d{4,8}\b", "drivers_license"),
        (r"(?i)\b(?:internal\s+use\s+only|proprietary|confidential)\b", "sensitivity_marker"),
    ],
}

# File type sensitivity defaults
FILE_TYPE_SENSITIVITY = {
    ".pem": "restricted", ".key": "restricted", ".p12": "restricted", ".pfx": "restricted",
    ".env": "confidential", ".cfg": "internal", ".conf": "internal",
    ".csv": "internal", ".xlsx": "internal", ".xls": "internal",
    ".sql": "confidential", ".db": "confidential", ".sqlite": "confidential",
    ".doc": "internal", ".docx": "internal", ".pdf": "internal",
}


class DataClassifier:
    """Classifies content into sensitivity levels with custom label support."""

    def __init__(self, custom_labels: Optional[List[dict]] = None):
        self.custom_labels = custom_labels or []
        self._compiled_patterns = self._compile_patterns()
        self._custom_compiled = self._compile_custom_labels()

    def _compile_patterns(self):
        compiled = {}
        for level, patterns in SENSITIVITY_PATTERNS.items():
            compiled[level] = [(re.compile(p), label) for p, label in patterns]
        return compiled

    def _compile_custom_labels(self):
        compiled = []
        for label in self.custom_labels:
            patterns = []
            for p in label.get("patterns", []):
                try:
                    patterns.append(re.compile(p, re.IGNORECASE))
                except re.error:
                    pass
            compiled.append({
                "name": label["name"],
                "severity": label.get("severity", "internal"),
                "patterns": patterns,
                "description": label.get("description", ""),
            })
        return compiled

    def classify_text(self, text: str, file_path: Optional[str] = None) -> ClassificationResult:
        """Classify text content into a sensitivity level."""
        if not text:
            return ClassificationResult(level="public", confidence=0.0)

        # Check custom labels first (higher priority than auto)
        custom_result = self._check_custom_labels(text)
        if custom_result:
            return custom_result

        # Auto-classify based on patterns
        highest_level = "public"
        all_findings = []
        all_labels = []
        level_order = ["public", "internal", "confidential", "restricted", "top_secret"]

        for level in reversed(level_order[1:]):  # Check from highest to lowest
            for pattern, label in self._compiled_patterns.get(level, []):
                matches = pattern.findall(text)
                if matches:
                    all_findings.append({"label": label, "level": level, "count": len(matches)})
                    all_labels.append(label)
                    if level_order.index(level) > level_order.index(highest_level):
                        highest_level = level

        # Also check file extension if provided
        if file_path:
            ext = "." + file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
            file_level = FILE_TYPE_SENSITIVITY.get(ext)
            if file_level and level_order.index(file_level) > level_order.index(highest_level):
                highest_level = file_level
                all_findings.append({"label": f"file_type:{ext}", "level": file_level, "count": 1})

        confidence = min(len(all_findings) * 0.2, 1.0) if all_findings else 0.0

        return ClassificationResult(
            level=highest_level,
            labels=all_labels,
            findings=all_findings,
            confidence=confidence,
            source="auto",
        )

    def _check_custom_labels(self, text: str) -> Optional[ClassificationResult]:
        for cl in self._custom_compiled:
            for pattern in cl["patterns"]:
                if pattern.search(text):
                    return ClassificationResult(
                        level=cl["severity"],
                        labels=[cl["name"]],
                        findings=[{"label": cl["name"], "level": cl["severity"], "count": 1}],
                        confidence=0.9,
                        source="custom_label",
                        custom_label=cl["name"],
                    )
        return None

    def classify_file(self, file_path: str, max_bytes: int = 1048576) -> ClassificationResult:
        """Classify a file by reading and scanning its content."""
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read(max_bytes)
            return self.classify_text(content, file_path=file_path)
        except Exception:
            # Binary file or unreadable; classify by extension only
            ext = "." + file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
            level = FILE_TYPE_SENSITIVITY.get(ext, "public")
            return ClassificationResult(level=level, source="file_type", confidence=0.3)

    def update_custom_labels(self, labels: List[dict]):
        """Update custom classification labels (from control plane sync)."""
        self.custom_labels = labels
        self._custom_compiled = self._compile_custom_labels()
