#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
VALUES_FILE = ROOT / "infra/helm/cyberarmor/values.yaml"
INGRESS_TEMPLATE = ROOT / "infra/helm/cyberarmor/templates/ingress.yaml"


def main() -> int:
    issues: list[str] = []

    values = yaml.safe_load(VALUES_FILE.read_text(encoding="utf-8", errors="ignore")) or {}
    ingress_vals = values.get("ingress") or {}
    tls_vals = ingress_vals.get("tls") or {}
    mtls_vals = ingress_vals.get("mtls") or {}

    if "mtls" not in ingress_vals:
        issues.append("values.yaml missing ingress.mtls block")
    else:
        for key in ("enabled", "caSecretName", "verifyDepth", "passCertificateToUpstream"):
            if key not in mtls_vals:
                issues.append(f"values.yaml missing ingress.mtls.{key}")

    if tls_vals.get("enabled") is not True:
        issues.append("values.yaml ingress.tls.enabled should be true for gateway TLS baseline")

    template = INGRESS_TEMPLATE.read_text(encoding="utf-8", errors="ignore")
    required_markers = [
        "nginx.ingress.kubernetes.io/auth-tls-verify-client",
        "nginx.ingress.kubernetes.io/auth-tls-secret",
        "nginx.ingress.kubernetes.io/auth-tls-verify-depth",
        "nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream",
        "nginx.ingress.kubernetes.io/force-ssl-redirect",
    ]
    for marker in required_markers:
        if marker not in template:
            issues.append(f"ingress template missing marker: {marker}")

    if issues:
        print("GATEWAY_MTLS_POLICY_CHECK_FAILED")
        for issue in issues:
            print(f" - {issue}")
        return 1

    print("GATEWAY_MTLS_POLICY_CHECK_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
