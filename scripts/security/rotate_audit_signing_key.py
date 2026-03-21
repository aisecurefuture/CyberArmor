#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path


def _read_env(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="ignore").splitlines()


def _set_kv(lines: list[str], key: str, value: str) -> list[str]:
    prefix = f"{key}="
    out = []
    replaced = False
    for line in lines:
        if line.startswith(prefix):
            out.append(f"{key}={value}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"{key}={value}")
    return out


def _get(lines: list[str], key: str, default: str = "") -> str:
    prefix = f"{key}="
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):]
    return default


def main() -> int:
    parser = argparse.ArgumentParser(description="Rotate audit signing keys in env file.")
    parser.add_argument("--env-file", default="infra/docker-compose/.env")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    env_path = Path(args.env_file)
    lines = _read_env(env_path)

    active_key = _get(lines, "CYBERARMOR_AUDIT_SIGNING_KEY", _get(lines, "AUDIT_API_SECRET", ""))
    active_kid = _get(lines, "CYBERARMOR_AUDIT_SIGNING_KEY_ID", "k1")
    next_key = _get(lines, "CYBERARMOR_AUDIT_NEXT_SIGNING_KEY", "")
    next_kid = _get(lines, "CYBERARMOR_AUDIT_NEXT_SIGNING_KEY_ID", "k2")

    if not next_key:
        next_key = secrets.token_urlsafe(48)
    if not next_kid:
        next_kid = f"{active_kid}_next"

    # Promote staged -> active, mint new staged key.
    new_active_key = next_key
    new_active_kid = next_kid
    new_next_key = secrets.token_urlsafe(48)
    new_next_kid = f"{new_active_kid}_next"

    updated = list(lines)
    updated = _set_kv(updated, "CYBERARMOR_AUDIT_SIGNING_KEY", new_active_key)
    updated = _set_kv(updated, "CYBERARMOR_AUDIT_SIGNING_KEY_ID", new_active_kid)
    updated = _set_kv(updated, "CYBERARMOR_AUDIT_NEXT_SIGNING_KEY", new_next_key)
    updated = _set_kv(updated, "CYBERARMOR_AUDIT_NEXT_SIGNING_KEY_ID", new_next_kid)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = env_path.with_suffix(env_path.suffix + f".bak.{ts}")

    print("AUDIT_KEY_ROTATION_PLAN")
    print(f" - env_file: {env_path}")
    print(f" - old_active_kid: {active_kid or '(unset)'}")
    print(f" - new_active_kid: {new_active_kid}")
    print(f" - new_next_kid: {new_next_kid}")
    print(f" - backup: {backup}")

    if args.dry_run:
        print("DRY_RUN: no file changes made")
        return 0

    if env_path.exists():
        backup.write_text("\n".join(lines) + "\n", encoding="utf-8")
    env_path.write_text("\n".join(updated) + "\n", encoding="utf-8")
    print("ROTATION_APPLIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
