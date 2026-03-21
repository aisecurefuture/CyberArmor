#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import tempfile
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List


@dataclass
class RotationItem:
    name: str
    ref: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_items(raw: str) -> List[RotationItem]:
    if not raw.strip():
        return []
    # Accept JSON list of {"name":"...","ref":"..."} or comma-separated refs.
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            out: List[RotationItem] = []
            for idx, item in enumerate(data):
                if isinstance(item, dict):
                    ref = str(item.get("ref", "")).strip()
                    if not ref:
                        continue
                    name = str(item.get("name", f"secret_{idx+1}")).strip() or f"secret_{idx+1}"
                    out.append(RotationItem(name=name, ref=ref))
            return out
    except Exception:
        pass

    refs = [p.strip() for p in raw.split(",") if p.strip()]
    return [RotationItem(name=f"secret_{i+1}", ref=r) for i, r in enumerate(refs)]


def _print_plan(provider: str, apply: bool, items: List[RotationItem]) -> None:
    mode = "APPLY" if apply else "DRY_RUN"
    print(f"SECRET_MANAGER_ROTATION_{mode}")
    print(f" - timestamp: {_now()}")
    print(f" - provider: {provider}")
    print(f" - item_count: {len(items)}")
    for item in items:
        print(f" - rotate: {item.name} -> {item.ref}")


def _rotate_aws(ref: str, apply: bool) -> dict:
    secret_id, version = _split_ref(ref)
    cmd = ["aws", "secretsmanager", "rotate-secret", "--secret-id", secret_id]
    if version:
        cmd.extend(["--client-request-token", version])
    return _run_provider_cmd("aws", cmd, apply)


def _rotate_azure(ref: str, apply: bool, generated_value: str) -> dict:
    # expected ref format: <vault-name>/<secret-name>
    core, _ = _split_ref(ref)
    parts = core.split("/", 1)
    if len(parts) != 2:
        return {"provider": "azure", "ok": False, "error": "invalid_ref_format"}
    vault, secret = parts
    cmd = ["az", "keyvault", "secret", "set", "--vault-name", vault, "--name", secret, "--value", generated_value]
    return _run_provider_cmd("azure", cmd, apply)


def _rotate_gcp(ref: str, apply: bool, generated_value: str) -> dict:
    core, _ = _split_ref(ref)
    parsed = _parse_gcp_secret_ref(core)
    if not parsed:
        return {"provider": "gcp", "ok": False, "error": "invalid_ref_format"}
    project, secret = parsed
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as tmp:
        tmp.write(generated_value)
        tmp_path = tmp.name
    cmd = ["gcloud", "secrets", "versions", "add", secret, f"--project={project}", f"--data-file={tmp_path}"]
    return _run_provider_cmd("gcp", cmd, apply)


def _promote_aws(ref: str, apply: bool) -> dict:
    secret_id, version = _split_ref(ref)
    if not version:
        return {"provider": "aws", "ok": False, "error": "missing_version_for_promote"}
    cmd = [
        "aws", "secretsmanager", "update-secret-version-stage",
        "--secret-id", secret_id,
        "--version-stage", "AWSCURRENT",
        "--move-to-version-id", version,
    ]
    return _run_provider_cmd("aws", cmd, apply)


def _promote_azure(ref: str, apply: bool) -> dict:
    core, version = _split_ref(ref)
    parts = core.split("/", 1)
    if len(parts) != 2 or not version:
        return {"provider": "azure", "ok": False, "error": "missing_version_for_promote"}
    vault, secret = parts
    versioned_id = f"https://{vault}.vault.azure.net/secrets/{secret}/{version}"
    cmd = ["az", "keyvault", "secret", "set-attributes", "--id", versioned_id, "--enabled", "true"]
    return _run_provider_cmd("azure", cmd, apply)


def _promote_gcp(ref: str, apply: bool) -> dict:
    core, version = _split_ref(ref)
    parsed = _parse_gcp_secret_ref(core)
    if not parsed or not version:
        return {"provider": "gcp", "ok": False, "error": "missing_version_for_promote"}
    project, secret = parsed
    cmd = ["gcloud", "secrets", "versions", "enable", version, f"--secret={secret}", f"--project={project}"]
    return _run_provider_cmd("gcp", cmd, apply)


def _rollback_aws(ref: str, apply: bool) -> dict:
    # rollback is equivalent to promoting previous known good version
    return _promote_aws(ref, apply)


def _rollback_azure(ref: str, apply: bool) -> dict:
    # rollback is equivalent to promoting a specified version
    return _promote_azure(ref, apply)


def _rollback_gcp(ref: str, apply: bool) -> dict:
    # rollback is equivalent to promoting a specified version
    return _promote_gcp(ref, apply)


def _run_provider_cmd(provider: str, cmd: list[str], apply: bool) -> dict:
    tool = cmd[0]
    if shutil.which(tool) is None:
        return {"provider": provider, "ok": False, "error": f"{tool}_not_found", "cmd": cmd}
    if not apply:
        return {"provider": provider, "ok": True, "mode": "dry_run", "cmd": cmd}
    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return {
            "provider": provider,
            "ok": True,
            "mode": "apply",
            "cmd": cmd,
            "stdout": (proc.stdout or "")[:2000],
            "stderr": (proc.stderr or "")[:2000],
        }
    except subprocess.CalledProcessError as exc:
        return {
            "provider": provider,
            "ok": False,
            "mode": "apply",
            "cmd": cmd,
            "stdout": (exc.stdout or "")[:2000],
            "stderr": (exc.stderr or "")[:2000],
            "returncode": exc.returncode,
        }


def _split_ref(ref: str) -> tuple[str, str]:
    if "@" not in ref:
        return ref, ""
    core, version = ref.rsplit("@", 1)
    return core, version


def _parse_gcp_secret_ref(ref: str) -> tuple[str, str] | None:
    # projects/<project>/secrets/<secret>
    parts = ref.strip().split("/")
    if len(parts) != 4:
        return None
    if parts[0] != "projects" or parts[2] != "secrets":
        return None
    return parts[1], parts[3]


def main() -> int:
    parser = argparse.ArgumentParser(description="Secret-manager-backed rotation execution helper.")
    parser.add_argument("--provider", required=True, choices=["aws", "azure", "gcp"])
    parser.add_argument("--operation", required=True, choices=["rotate", "promote", "rollback"])
    parser.add_argument("--items", required=True, help="JSON list or comma-separated secret refs")
    parser.add_argument("--apply", action="store_true", help="Execute rotation mode")
    parser.add_argument("--approval-token", default="", help="Approval token for apply mode")
    parser.add_argument("--artifact-file", default="artifacts/security-rotation-evidence.json")
    parser.add_argument("--approval-environment", default=os.getenv("GITHUB_ENVIRONMENT", "security-approval"))
    parser.add_argument("--approval-actor", default=os.getenv("GITHUB_ACTOR", "unknown"))
    parser.add_argument("--change-ticket", default=os.getenv("CYBERARMOR_CHANGE_TICKET", ""))
    args = parser.parse_args()

    items = _parse_items(args.items)
    if not items:
        print("No rotation items provided.")
        return 2

    if args.apply:
        expected = os.getenv("CYBERARMOR_ROTATION_APPROVAL_TOKEN", "").strip()
        if not expected:
            print("Missing CYBERARMOR_ROTATION_APPROVAL_TOKEN in environment.")
            return 3
        if args.approval_token.strip() != expected:
            print("Approval token mismatch. Refusing apply mode.")
            return 4

    _print_plan(args.provider, args.apply, items)
    print(f" - operation: {args.operation}")

    results = []
    for item in items:
        generated = secrets.token_urlsafe(48)
        if args.operation == "rotate":
            if args.provider == "aws":
                result = _rotate_aws(item.ref, args.apply)
            elif args.provider == "azure":
                result = _rotate_azure(item.ref, args.apply, generated)
            else:
                result = _rotate_gcp(item.ref, args.apply, generated)
        elif args.operation == "promote":
            if args.provider == "aws":
                result = _promote_aws(item.ref, args.apply)
            elif args.provider == "azure":
                result = _promote_azure(item.ref, args.apply)
            else:
                result = _promote_gcp(item.ref, args.apply)
        else:
            if args.provider == "aws":
                result = _rollback_aws(item.ref, args.apply)
            elif args.provider == "azure":
                result = _rollback_azure(item.ref, args.apply)
            else:
                result = _rollback_gcp(item.ref, args.apply)
        result["name"] = item.name
        result["ref"] = item.ref
        results.append(result)

    approval_meta = {
        "apply": args.apply,
        "environment": args.approval_environment,
        "actor": args.approval_actor,
        "token_provided": bool(args.approval_token.strip()) if args.apply else False,
    }
    approval_sig = None
    if args.apply:
        canonical = json.dumps(approval_meta, sort_keys=True).encode()
        approval_sig = hmac.new(args.approval_token.encode(), canonical, hashlib.sha256).hexdigest()

    evidence = {
        "timestamp": _now(),
        "provider": args.provider,
        "operation": args.operation,
        "apply": args.apply,
        "items": [item.__dict__ for item in items],
        "results": results,
        "approval": {
            **approval_meta,
            "signature": approval_sig,
            "signature_algorithm": "hmac-sha256" if approval_sig else None,
        },
        "change_ticket": args.change_ticket or None,
    }
    artifact_path = Path(args.artifact_file)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"ROTATION_EVIDENCE_WRITTEN {artifact_path}")

    if any(not r.get("ok", False) for r in results):
        print("ROTATION_EXECUTION_FAILED")
        return 5

    print("ROTATION_EXECUTION_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
