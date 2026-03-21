#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INTEGRATION_MAIN = ROOT / "services/integration-control/main.py"
INTEGRATION_README = ROOT / "services/integration-control/README.md"
ONBOARD_RUNBOOK = ROOT / "docs/runbooks/integration-onboarding-policy-gated-runbook.md"
CONTROL_PLANE_MAIN = ROOT / "services/control-plane/main.py"
COMPOSE_FILE = ROOT / "infra/docker-compose/docker-compose.yml"


def _contains(path: Path, markers: list[str], issues: list[str], label: str) -> None:
    text = path.read_text(encoding="utf-8", errors="ignore")
    for marker in markers:
        if marker not in text:
            issues.append(f"{label} missing marker: {marker}")


def main() -> int:
    issues: list[str] = []

    required_files = [
        INTEGRATION_MAIN,
        INTEGRATION_README,
        ONBOARD_RUNBOOK,
        CONTROL_PLANE_MAIN,
        COMPOSE_FILE,
    ]
    for p in required_files:
        if not p.exists():
            issues.append(f"missing file: {p.relative_to(ROOT)}")
    if issues:
        _fail(issues)
        return 1

    _contains(
        INTEGRATION_MAIN,
        [
            "/integrations/providers",
            "/integrations/discovery/run",
            "/integrations/policy/evaluate",
            "/integrations/providers/microsoft365/configure",
            "/integrations/providers/google-workspace/configure",
            "/integrations/providers/salesforce/configure",
            "/integrations/providers/agentic-ai/configure",
        ],
        issues,
        "integration-control main",
    )
    _contains(
        CONTROL_PLANE_MAIN,
        [
            "/integrations/onboard",
            "INTEGRATION_CONTROL_URL",
            "/integrations/policy/evaluate",
        ],
        issues,
        "control-plane main",
    )
    _contains(
        ONBOARD_RUNBOOK,
        [
            "POST /integrations/onboard",
            "provider\": \"microsoft365\"",
            "provider\": \"google_workspace\"",
            "provider\": \"salesforce\"",
            "provider\": \"agentic_ai\"",
        ],
        issues,
        "onboarding runbook",
    )
    _contains(
        COMPOSE_FILE,
        [
            "integration-control:",
            "services/integration-control/Dockerfile",
            "8012:8012",
        ],
        issues,
        "docker-compose",
    )

    if issues:
        _fail(issues)
        return 1

    print("INTEGRATION_CONTROL_POLICY_CHECK_OK")
    return 0


def _fail(issues: list[str]) -> None:
    print("INTEGRATION_CONTROL_POLICY_CHECK_FAILED")
    for issue in issues:
        print(f" - {issue}")


if __name__ == "__main__":
    raise SystemExit(main())

