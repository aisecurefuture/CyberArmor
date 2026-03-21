#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

REQUIRED_FILES = [
    ROOT / "scripts/security/generate_mtls_materials.sh",
    ROOT / "scripts/security/rotate_audit_signing_key.py",
    ROOT / ".github/workflows/ci-security-rotation-drill.yml",
    ROOT / "docs/runbooks/mtls-certificate-rotation-runbook.md",
    ROOT / "docs/runbooks/audit-signing-key-rotation-and-retention-lock.md",
]


def main() -> int:
    missing = [str(p.relative_to(ROOT)) for p in REQUIRED_FILES if not p.exists()]
    if missing:
        print("ROTATION_PIPELINE_CHECK_FAILED")
        for m in missing:
            print(f" - missing: {m}")
        return 1
    print("ROTATION_PIPELINE_CHECK_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
