#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ENV_EXAMPLE = ROOT / "infra/docker-compose/.env.example"
LAUNCHER = ROOT / "scripts/security/run_uvicorn_tls.py"

DOCKERFILES = [
    ROOT / "services/control-plane/Dockerfile",
    ROOT / "services/policy/Dockerfile",
    ROOT / "services/agent-identity/Dockerfile",
    ROOT / "services/ai-router/Dockerfile",
    ROOT / "services/audit/Dockerfile",
    ROOT / "services/runtime/Dockerfile",
    ROOT / "agents/proxy-agent/Dockerfile",
]


def main() -> int:
    issues: list[str] = []

    if not LAUNCHER.exists():
        issues.append("missing scripts/security/run_uvicorn_tls.py")

    env_text = ENV_EXAMPLE.read_text(encoding="utf-8", errors="ignore")
    for key in ("CYBERARMOR_ENABLE_NATIVE_TLS_LISTENER", "CYBERARMOR_REQUIRE_CLIENT_CERT"):
        if f"{key}=" not in env_text:
            issues.append(f".env.example missing {key}")

    for dockerfile in DOCKERFILES:
        if not dockerfile.exists():
            issues.append(f"missing dockerfile: {dockerfile.relative_to(ROOT)}")
            continue
        text = dockerfile.read_text(encoding="utf-8", errors="ignore")
        if "run_uvicorn_tls.py" not in text:
            issues.append(f"{dockerfile.relative_to(ROOT)} missing run_uvicorn_tls.py wiring")

    if issues:
        print("NATIVE_TLS_LISTENER_POLICY_CHECK_FAILED")
        for issue in issues:
            print(f" - {issue}")
        return 1

    print("NATIVE_TLS_LISTENER_POLICY_CHECK_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
