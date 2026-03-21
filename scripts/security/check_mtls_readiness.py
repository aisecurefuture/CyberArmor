#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ENV_EXAMPLE = ROOT / "infra/docker-compose/.env.example"
COMPOSE = ROOT / "infra/docker-compose/docker-compose.yml"

REQUIRED_ENV_KEYS = [
    "CYBERARMOR_ENFORCE_MTLS",
    "CYBERARMOR_TLS_CA_FILE",
    "CYBERARMOR_TLS_CERT_FILE",
    "CYBERARMOR_TLS_KEY_FILE",
]
REQUIRED_CERT_MOUNT_SERVICES = [
    "control-plane",
    "policy",
    "runtime",
    "agent-identity",
    "ai-router",
    "audit",
    "proxy-agent",
    "transparent-proxy",
]


def _check_env_example(text: str) -> list[str]:
    missing = []
    for key in REQUIRED_ENV_KEYS:
        if re.search(rf"(?m)^{re.escape(key)}=", text) is None:
            missing.append(f".env.example missing {key}")
    return missing


def _check_compose(text: str) -> list[str]:
    missing = []
    for svc in REQUIRED_CERT_MOUNT_SERVICES:
        block_match = re.search(
            rf"(?ms)^  {re.escape(svc)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)",
            text,
        )
        if not block_match:
            missing.append(f"docker-compose missing service block: {svc}")
            continue
        block = block_match.group(1)
        if "certs:/etc/cyberarmor/tls:ro" not in block:
            missing.append(f"{svc} missing certs volume mount")
    return missing


def main() -> int:
    issues: list[str] = []
    issues.extend(_check_env_example(ENV_EXAMPLE.read_text(encoding="utf-8", errors="ignore")))
    issues.extend(_check_compose(COMPOSE.read_text(encoding="utf-8", errors="ignore")))

    if issues:
        print("MTLS_READINESS_CHECK_FAILED")
        for issue in issues:
            print(f" - {issue}")
        return 1

    print("MTLS_READINESS_CHECK_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
