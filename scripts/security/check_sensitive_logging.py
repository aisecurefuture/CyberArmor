#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SERVICES = ROOT / "services"

LOG_CALL_RE = re.compile(
    r"\b(?:logger|logging)\.(?:debug|info|warning|error|critical)\s*\((?P<body>.*?)\)",
    re.DOTALL,
)
SENSITIVE_KEYWORDS = (
    "api_key",
    "apikey",
    "secret",
    "password",
    "token",
    "bearer",
    "authorization",
    "private_key",
)
ALLOWLIST_SNIPPETS = (
    "missing api key",
    "invalid api key",
    "token validation status",
)


def _python_files() -> list[Path]:
    return sorted(p for p in SERVICES.rglob("*.py") if p.is_file())


def _line_of_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def main() -> int:
    findings: list[str] = []

    for py in _python_files():
        text = py.read_text(encoding="utf-8", errors="ignore")
        lowered = text.lower()
        for m in LOG_CALL_RE.finditer(lowered):
            body = m.group("body")
            if any(allow in body for allow in ALLOWLIST_SNIPPETS):
                continue
            if any(keyword in body for keyword in SENSITIVE_KEYWORDS):
                line = _line_of_offset(text, m.start())
                findings.append(f"{py.relative_to(ROOT)}:{line}: potential sensitive logging pattern")

    if findings:
        print("SENSITIVE_LOGGING_CHECK_FAILED")
        for f in findings:
            print(f" - {f}")
        return 1

    print("SENSITIVE_LOGGING_CHECK_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
