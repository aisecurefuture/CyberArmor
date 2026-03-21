#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci-security-rotation-approval.yml"
SCRIPT = ROOT / "scripts/security/rotate_secrets_with_manager.py"
RUNBOOK = ROOT / "docs/runbooks/secret-manager-rotation-approval-runbook.md"


def main() -> int:
    issues: list[str] = []

    if not SCRIPT.exists():
        issues.append("missing scripts/security/rotate_secrets_with_manager.py")
    if not WORKFLOW.exists():
        issues.append("missing .github/workflows/ci-security-rotation-approval.yml")
    if not RUNBOOK.exists():
        issues.append("missing docs/runbooks/secret-manager-rotation-approval-runbook.md")

    if WORKFLOW.exists():
        text = WORKFLOW.read_text(encoding="utf-8", errors="ignore")
        required_markers = [
            "workflow_dispatch:",
            "environment: security-approval",
            "SECURITY_ROTATION_APPROVAL_TOKEN",
            "permissions:",
            "id-token: write",
            "aws-actions/configure-aws-credentials@v4",
            "azure/login@v2",
            "google-github-actions/auth@v2",
            "operation:",
            "change_ticket:",
            "--apply",
            "--operation",
            "--approval-token",
            "--approval-environment",
            "--approval-actor",
            "--change-ticket",
            "--artifact-file",
            "actions/upload-artifact@v4",
            "security-rotation-evidence",
        ]
        for marker in required_markers:
            if marker not in text:
                issues.append(f"workflow missing marker: {marker}")

    if issues:
        print("SECRET_MANAGER_ROTATION_POLICY_CHECK_FAILED")
        for issue in issues:
            print(f" - {issue}")
        return 1

    print("SECRET_MANAGER_ROTATION_POLICY_CHECK_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
