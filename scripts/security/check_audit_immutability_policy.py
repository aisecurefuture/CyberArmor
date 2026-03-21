#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT_MAIN = ROOT / "services/audit/main.py"


def main() -> int:
    text = AUDIT_MAIN.read_text(encoding="utf-8", errors="ignore")
    issues: list[str] = []

    required_markers = [
        "ENFORCE_IMMUTABLE_RETENTION",
        "AUDIT_RETENTION_DAYS",
        "AUDIT_MIN_RETENTION_DAYS",
        "_enforce_immutability_retention_policy",
        "CYBERARMOR_AUDIT_SIGNING_KEY_ID",
        "CYBERARMOR_AUDIT_NEXT_SIGNING_KEY",
        "/integrity/signing-key/status",
    ]
    for marker in required_markers:
        if marker not in text:
            issues.append(f"audit policy marker missing: {marker}")

    # Guard against accidental upsert semantics in event ingestion path.
    banned_markers = [
        "ON CONFLICT DO UPDATE",
        ".merge(",
    ]
    for marker in banned_markers:
        if marker in text:
            issues.append(f"disallowed mutating marker present: {marker}")

    if issues:
        print("AUDIT_IMMUTABILITY_POLICY_CHECK_FAILED")
        for issue in issues:
            print(f" - {issue}")
        return 1

    print("AUDIT_IMMUTABILITY_POLICY_CHECK_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
