#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
AWS_POLICY = ROOT / "infra/security/iam/aws-rotation-policy.json"
AZURE_ROLE = ROOT / "infra/security/iam/azure-rotation-role.json"
GCP_ROLE = ROOT / "infra/security/iam/gcp-rotation-role.yaml"
WORKFLOW = ROOT / ".github/workflows/ci-security-rotation-approval.yml"
LIVE_WORKFLOW = ROOT / ".github/workflows/ci-security-iam-live-validation.yml"
LIVE_SCRIPT = ROOT / "scripts/security/validate_rotation_iam_live.py"
LIVE_RUNBOOK = ROOT / "docs/runbooks/rotation-iam-live-validation-runbook.md"


def main() -> int:
    issues: list[str] = []

    for p in (AWS_POLICY, AZURE_ROLE, GCP_ROLE, WORKFLOW, LIVE_WORKFLOW, LIVE_SCRIPT, LIVE_RUNBOOK):
        if not p.exists():
            issues.append(f"missing file: {p.relative_to(ROOT)}")
    if issues:
        _fail(issues)
        return 1

    aws = json.loads(AWS_POLICY.read_text(encoding="utf-8", errors="ignore"))
    aws_txt = json.dumps(aws)
    required_aws = [
        "secretsmanager:RotateSecret",
        "secretsmanager:UpdateSecretVersionStage",
        "secretsmanager:DescribeSecret",
        "secretsmanager:ListSecretVersionIds",
    ]
    for action in required_aws:
        if action not in aws_txt:
            issues.append(f"AWS policy missing action: {action}")
    if "\"*\"" in aws_txt:
        issues.append("AWS policy contains wildcard *; restrict resource/actions")

    azure = json.loads(AZURE_ROLE.read_text(encoding="utf-8", errors="ignore"))
    azure_actions = azure.get("Actions", [])
    required_az = {
        "Microsoft.KeyVault/vaults/secrets/read",
        "Microsoft.KeyVault/vaults/secrets/write",
        "Microsoft.KeyVault/vaults/secrets/versions/read",
    }
    for action in required_az:
        if action not in azure_actions:
            issues.append(f"Azure role missing action: {action}")

    gcp = yaml.safe_load(GCP_ROLE.read_text(encoding="utf-8", errors="ignore")) or {}
    gcp_perms = set(gcp.get("includedPermissions") or [])
    required_gcp = {
        "secretmanager.secrets.get",
        "secretmanager.versions.add",
        "secretmanager.versions.enable",
        "secretmanager.versions.get",
    }
    for perm in required_gcp:
        if perm not in gcp_perms:
            issues.append(f"GCP role missing permission: {perm}")

    wf_text = WORKFLOW.read_text(encoding="utf-8", errors="ignore")
    for marker in [
        "AWS_ROTATION_ROLE_ARN",
        "AZURE_ROTATION_CLIENT_ID",
        "GCP_ROTATION_WORKLOAD_ID_PROVIDER",
    ]:
        if marker not in wf_text:
            issues.append(f"workflow missing least-privilege identity marker: {marker}")

    live_wf_text = LIVE_WORKFLOW.read_text(encoding="utf-8", errors="ignore")
    for marker in [
        "workflow_dispatch:",
        "validate_rotation_iam_live.py",
        "security-rotation-iam-live-evidence",
        "id-token: write",
        "aws-actions/configure-aws-credentials@v4",
        "azure/login@v2",
        "google-github-actions/auth@v2",
    ]:
        if marker not in live_wf_text:
            issues.append(f"live IAM workflow missing marker: {marker}")

    if issues:
        _fail(issues)
        return 1
    print("ROTATION_IAM_LEAST_PRIVILEGE_CHECK_OK")
    return 0


def _fail(issues: list[str]) -> None:
    print("ROTATION_IAM_LEAST_PRIVILEGE_CHECK_FAILED")
    for issue in issues:
        print(f" - {issue}")


if __name__ == "__main__":
    raise SystemExit(main())
