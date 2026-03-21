#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
AWS_POLICY = ROOT / "infra/security/iam/aws-rotation-policy.json"
AZURE_ROLE = ROOT / "infra/security/iam/azure-rotation-role.json"
GCP_ROLE = ROOT / "infra/security/iam/gcp-rotation-role.yaml"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _load_aws_required_actions() -> list[str]:
    data = json.loads(AWS_POLICY.read_text(encoding="utf-8"))
    out: list[str] = []
    for stmt in data.get("Statement", []):
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if isinstance(action, str) and action.startswith("secretsmanager:"):
                out.append(action)
    return sorted(set(out))


def _load_azure_required_actions() -> list[str]:
    data = json.loads(AZURE_ROLE.read_text(encoding="utf-8"))
    actions = data.get("Actions", [])
    return sorted({a for a in actions if isinstance(a, str)})


def _load_gcp_required_permissions() -> list[str]:
    data = yaml.safe_load(GCP_ROLE.read_text(encoding="utf-8")) or {}
    perms = data.get("includedPermissions", []) or []
    return sorted({p for p in perms if isinstance(p, str)})


def _validate_aws(role_arn: str) -> tuple[bool, dict[str, Any]]:
    required = _load_aws_required_actions()
    prohibited = [
        "secretsmanager:DeleteSecret",
        "secretsmanager:PutResourcePolicy",
        "secretsmanager:TagResource",
    ]
    if not role_arn.strip():
        return False, {"provider": "aws", "error": "missing_role_arn", "required_actions": required}
    if shutil.which("aws") is None:
        return False, {"provider": "aws", "error": "aws_cli_not_found", "required_actions": required}

    cmd = [
        "aws",
        "iam",
        "simulate-principal-policy",
        "--policy-source-arn",
        role_arn,
        "--action-names",
        *(required + prohibited),
        "--output",
        "json",
    ]
    rc, out, err = _run(cmd)
    if rc != 0:
        return False, {"provider": "aws", "error": "simulate_failed", "returncode": rc, "stderr": err[:2000]}

    payload = json.loads(out or "{}")
    evals = payload.get("EvaluationResults", []) or []
    decisions: dict[str, str] = {}
    for item in evals:
        action = item.get("EvalActionName")
        decision = str(item.get("EvalDecision", "")).lower()
        if isinstance(action, str):
            decisions[action] = decision

    missing_required = [a for a in required if decisions.get(a) != "allowed"]
    allowed_prohibited = [a for a in prohibited if decisions.get(a) == "allowed"]
    ok = not missing_required and not allowed_prohibited
    return ok, {
        "provider": "aws",
        "role_arn": role_arn,
        "required_actions": required,
        "prohibited_actions": prohibited,
        "missing_required_actions": missing_required,
        "allowed_prohibited_actions": allowed_prohibited,
    }


def _validate_azure(role_name: str) -> tuple[bool, dict[str, Any]]:
    required = _load_azure_required_actions()
    if not role_name.strip():
        return False, {"provider": "azure", "error": "missing_role_name", "required_actions": required}
    if shutil.which("az") is None:
        return False, {"provider": "azure", "error": "az_cli_not_found", "required_actions": required}

    cmd = ["az", "role", "definition", "list", "--name", role_name, "--output", "json"]
    rc, out, err = _run(cmd)
    if rc != 0:
        return False, {"provider": "azure", "error": "role_query_failed", "returncode": rc, "stderr": err[:2000]}

    data = json.loads(out or "[]")
    role = data[0] if isinstance(data, list) and data else {}
    permissions = role.get("permissions", []) or []
    effective_actions: set[str] = set()
    for entry in permissions:
        for action in entry.get("actions", []) or []:
            if isinstance(action, str):
                effective_actions.add(action)

    missing_required = [a for a in required if a not in effective_actions]
    wildcard_actions = [a for a in effective_actions if a.strip() == "*"]
    ok = not missing_required and not wildcard_actions
    return ok, {
        "provider": "azure",
        "role_name": role_name,
        "required_actions": required,
        "missing_required_actions": missing_required,
        "wildcard_actions": wildcard_actions,
    }


def _validate_gcp(role_id: str) -> tuple[bool, dict[str, Any]]:
    required = _load_gcp_required_permissions()
    if not role_id.strip():
        return False, {"provider": "gcp", "error": "missing_role_id", "required_permissions": required}
    if shutil.which("gcloud") is None:
        return False, {"provider": "gcp", "error": "gcloud_not_found", "required_permissions": required}

    cmd = ["gcloud", "iam", "roles", "describe", role_id, "--format=json"]
    rc, out, err = _run(cmd)
    if rc != 0:
        return False, {"provider": "gcp", "error": "role_describe_failed", "returncode": rc, "stderr": err[:2000]}

    data = json.loads(out or "{}")
    effective = set(data.get("includedPermissions", []) or [])
    missing_required = [p for p in required if p not in effective]
    wildcard_permissions = [p for p in effective if p.strip() == "*"]
    ok = not missing_required and not wildcard_permissions
    return ok, {
        "provider": "gcp",
        "role_id": role_id,
        "required_permissions": required,
        "missing_required_permissions": missing_required,
        "wildcard_permissions": wildcard_permissions,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate live cloud IAM least-privilege posture for rotation identities.")
    parser.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    parser.add_argument("--aws-role-arn", default="")
    parser.add_argument("--azure-role-name", default="")
    parser.add_argument("--gcp-role-id", default="")
    parser.add_argument("--artifact-file", default="artifacts/security-rotation-iam-live-evidence.json")
    args = parser.parse_args()

    if args.provider == "aws":
        ok, details = _validate_aws(args.aws_role_arn)
    elif args.provider == "azure":
        ok, details = _validate_azure(args.azure_role_name)
    else:
        ok, details = _validate_gcp(args.gcp_role_id)

    evidence = {
        "timestamp": _now(),
        "provider": args.provider,
        "ok": ok,
        "details": details,
    }

    artifact_path = Path(args.artifact_file)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")

    if ok:
        print("ROTATION_IAM_LIVE_VALIDATION_OK")
        print(f" - provider: {args.provider}")
        print(f" - artifact: {artifact_path}")
        return 0

    print("ROTATION_IAM_LIVE_VALIDATION_FAILED")
    print(f" - provider: {args.provider}")
    print(f" - artifact: {artifact_path}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
