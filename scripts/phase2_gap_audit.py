#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple


ROOT = Path(__file__).resolve().parents[1]
OPENAPI_SPEC = ROOT / "docs/api/openapi.yaml"

CORE_SERVICE_FILES = {
    "agent-identity": ROOT / "services/agent-identity/main.py",
    "policy": ROOT / "services/policy/main.py",
    "ai-router": ROOT / "services/ai-router/main.py",
    "audit": ROOT / "services/audit/main.py",
}


@dataclass
class Check:
    name: str
    passed: bool
    details: str


def exists_all(paths: Iterable[Path], name: str) -> Check:
    missing = [str(p.relative_to(ROOT)) for p in paths if not p.exists()]
    if missing:
        return Check(name=name, passed=False, details=f"Missing: {', '.join(missing)}")
    return Check(name=name, passed=True, details="All required paths present")


def openapi_path_check() -> Check:
    if not OPENAPI_SPEC.exists():
        return Check("openapi_required_paths", False, "docs/api/openapi.yaml not found")
    text = OPENAPI_SPEC.read_text(encoding="utf-8", errors="ignore")
    required = [
        "/policies/evaluate",
        "/policies/{tenant_id}/evaluate",
        "/policies/evaluate/batch",
        "/policies/simulate",
        "/policies/import",
        "/policies/explain/{req_id}",
        "/ai/chat/completions",
        "/ai/completions",
        "/ai/embeddings",
        "/ai/images/generate",
        "/health",
        "/ready",
        "/metrics",
    ]
    missing = [p for p in required if not re.search(rf"^\s*{re.escape(p)}:\s*$", text, re.MULTILINE)]
    if missing:
        return Check("openapi_required_paths", False, f"Missing paths: {', '.join(missing)}")
    return Check("openapi_required_paths", True, "All required API paths present")


def _extract_fastapi_routes(path: Path) -> Set[Tuple[str, str]]:
    if not path.exists():
        return set()
    text = path.read_text(encoding="utf-8", errors="ignore")
    routes: Set[Tuple[str, str]] = set()
    for method, route in re.findall(r'@app\.(get|post|put|delete|patch)\("([^"]+)"', text):
        routes.add((method.lower(), route))
    for route, methods_blob in re.findall(r'@app\.api_route\("([^"]+)",\s*methods=\[([^\]]+)\]', text):
        methods = re.findall(r'"([A-Z]+)"', methods_blob)
        for method in methods:
            routes.add((method.lower(), route))
    return routes


def _extract_openapi_methods(spec_text: str) -> Dict[str, Set[str]]:
    lines = spec_text.splitlines()
    out: Dict[str, Set[str]] = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        m_path = re.match(r"^\s{2}(/[^:]+):\s*$", line)
        if not m_path:
            i += 1
            continue
        path = m_path.group(1)
        out.setdefault(path, set())
        i += 1
        while i < len(lines):
            nxt = lines[i]
            if re.match(r"^\s{2}/[^:]+:\s*$", nxt):
                break
            m_method = re.match(r"^\s{4}(get|post|put|delete|patch|options|head):\s*$", nxt)
            if m_method:
                out[path].add(m_method.group(1))
            i += 1
    return out


def openapi_core_service_parity_check() -> Check:
    if not OPENAPI_SPEC.exists():
        return Check("openapi_core_service_parity", False, "docs/api/openapi.yaml not found")
    spec_text = OPENAPI_SPEC.read_text(encoding="utf-8", errors="ignore")
    spec_methods = _extract_openapi_methods(spec_text)

    required_routes: List[Tuple[str, str, str]] = [
        ("agent-identity", "post", "/agents/register"),
        ("agent-identity", "get", "/agents"),
        ("agent-identity", "get", "/agents/{agent_id}"),
        ("agent-identity", "post", "/agents/{agent_id}/tokens/issue"),
        ("agent-identity", "post", "/agents/{agent_id}/tokens/validate"),
        ("agent-identity", "post", "/agents/{agent_id}/tokens/revoke"),
        ("agent-identity", "post", "/delegations"),
        ("agent-identity", "delete", "/delegations/{chain_id}"),
        ("policy", "post", "/policies/evaluate"),
        ("policy", "post", "/policies/{tenant_id}/evaluate"),
        ("policy", "post", "/policies/evaluate/batch"),
        ("policy", "get", "/policies/simulate"),
        ("policy", "post", "/policies/import"),
        ("policy", "get", "/policies/explain/{req_id}"),
        ("ai-router", "post", "/ai/chat/completions"),
        ("ai-router", "post", "/ai/messages"),
        ("ai-router", "post", "/ai/completions"),
        ("ai-router", "post", "/ai/embeddings"),
        ("ai-router", "post", "/ai/images/generate"),
        ("ai-router", "get", "/ai/models"),
        ("ai-router", "get", "/ai/providers"),
        ("ai-router", "post", "/credentials/providers/{provider}/configure"),
        ("ai-router", "get", "/credentials/providers/{provider}/status"),
        ("ai-router", "post", "/credentials/providers/{provider}/rotate"),
        ("audit", "post", "/events"),
        ("audit", "post", "/events/batch"),
        ("audit", "get", "/events"),
        ("audit", "get", "/traces/{trace_id}"),
        ("audit", "get", "/graph/agent/{agent_id}"),
        ("audit", "get", "/integrity/verify/{event_id}"),
    ]

    service_routes: Dict[str, Set[Tuple[str, str]]] = {
        name: _extract_fastapi_routes(path) for name, path in CORE_SERVICE_FILES.items()
    }
    missing_service: List[str] = []
    missing_spec: List[str] = []

    for svc, method, path in required_routes:
        if (method, path) not in service_routes.get(svc, set()):
            missing_service.append(f"{svc} {method.upper()} {path}")
        if method not in spec_methods.get(path, set()):
            missing_spec.append(f"openapi {method.upper()} {path}")

    if missing_service or missing_spec:
        details = []
        if missing_service:
            details.append(f"missing in service: {', '.join(missing_service)}")
        if missing_spec:
            details.append(f"missing in openapi: {', '.join(missing_spec)}")
        return Check("openapi_core_service_parity", False, "; ".join(details))
    return Check("openapi_core_service_parity", True, "Core service route-method parity validated against OpenAPI")


def service_contract_check() -> Check:
    services_root = ROOT / "services"
    if not services_root.exists():
        return Check("service_health_ready_metrics", False, "services directory missing")
    failing = []
    for svc in sorted([p for p in services_root.iterdir() if p.is_dir()]):
        corpus = ""
        for f in svc.rglob("*.py"):
            corpus += f.read_text(encoding="utf-8", errors="ignore") + "\n"
        for f in svc.rglob("*.ts"):
            corpus += f.read_text(encoding="utf-8", errors="ignore") + "\n"
        for f in svc.rglob("*.js"):
            corpus += f.read_text(encoding="utf-8", errors="ignore") + "\n"
        missing = []
        if "/health" not in corpus:
            missing.append("/health")
        if "/ready" not in corpus:
            missing.append("/ready")
        if "/metrics" not in corpus:
            missing.append("/metrics")
        if missing:
            failing.append(f"{svc.name}: missing {', '.join(missing)}")
    if failing:
        return Check("service_health_ready_metrics", False, "; ".join(failing))
    return Check("service_health_ready_metrics", True, "All services expose health/ready/metrics strings")


def sdk_surface_parity_check() -> Check:
    sdks = [
        "python",
        "java",
        "go",
        "nodejs",
        "dotnet",
        "ruby",
        "php",
        "rust",
        "c_cpp",
    ]
    providers = ["openai", "anthropic", "google", "amazon", "microsoft", "xai", "meta", "perplexity"]
    provider_requirements = {
        "python": providers,
        "java": providers,
        "go": providers,
        "nodejs": providers,
        "dotnet": providers,
        "ruby": providers,
        "php": providers,
        "rust": providers,
        "c_cpp": ["openai"],
    }
    framework_requirements = {
        "python": ["langchain", "llamaindex", "vercel"],
        "java": ["langchain", "llamaindex", "vercel"],
        "go": ["langchain", "llamaindex", "vercel"],
        "nodejs": ["langchain", "llamaindex", "vercel"],
        "dotnet": ["semantic", "llamaindex", "vercel"],
    }

    missing_dirs = []
    provider_gaps = []
    framework_gaps = []
    for sdk in sdks:
        sdk_dir = ROOT / "sdks" / sdk
        if not sdk_dir.exists():
            missing_dirs.append(sdk)
            continue
        corpus_parts: List[str] = []
        for p in sdk_dir.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() not in {".py", ".ts", ".js", ".go", ".cs", ".java", ".rb", ".php", ".rs", ".c", ".cpp", ".h", ".hpp", ".md", ".toml", ".json", ".xml"}:
                continue
            corpus_parts.append(str(p).lower())
            try:
                corpus_parts.append(p.read_text(encoding="utf-8", errors="ignore").lower())
            except Exception:
                pass
        corpus = "\n".join(corpus_parts)
        for provider in provider_requirements.get(sdk, []):
            if provider not in corpus:
                provider_gaps.append(f"{sdk}:{provider}")
        if sdk in framework_requirements:
            for framework in framework_requirements[sdk]:
                if framework not in corpus:
                    framework_gaps.append(f"{sdk}:{framework}")

    if missing_dirs or provider_gaps or framework_gaps:
        details: List[str] = []
        if missing_dirs:
            details.append(f"missing sdk dirs: {', '.join(missing_dirs)}")
        if provider_gaps:
            details.append(f"provider marker gaps: {', '.join(provider_gaps[:12])}{' ...' if len(provider_gaps) > 12 else ''}")
        if framework_gaps:
            details.append(f"framework marker gaps: {', '.join(framework_gaps)}")
        return Check("sdk_surface_parity", False, "; ".join(details))
    return Check("sdk_surface_parity", True, "SDK provider/framework marker parity validated across languages")


def dashboard_presence_check() -> Check:
    dashboard = ROOT / "admin-dashboard"
    if not dashboard.exists():
        return Check("dashboard_presence", False, "admin-dashboard directory missing")
    route_markers = ["agent", "policy", "audit", "provider", "token", "delegation", "graph"]
    corpus_parts = []
    for p in dashboard.rglob("*"):
        if not p.is_file():
            continue
        corpus_parts.append(str(p).lower())
        try:
            corpus_parts.append(p.read_text(encoding="utf-8", errors="ignore").lower())
        except Exception:
            pass
    corpus = "\n".join(corpus_parts)
    found = sorted({m for m in route_markers if m in corpus})
    if len(found) < 7:
        return Check("dashboard_presence", False, f"Insufficient dashboard view markers: {found}")
    return Check("dashboard_presence", True, f"Dashboard markers found: {found}")


def infra_readiness_check() -> Check:
    helm_root = ROOT / "infra/helm/cyberarmor"
    tf_root = ROOT / "infra/terraform"
    missing: List[str] = []
    for rel in [
        "Chart.yaml",
        "values.yaml",
        "templates/hpa.yaml",
        "templates/pdb.yaml",
        "templates/networkpolicy.yaml",
        "templates/ingress.yaml",
        "templates/services-deployments.yaml",
    ]:
        if not (helm_root / rel).exists():
            missing.append(f"helm/{rel}")
    for rel in [
        "environments/prod/main.tf",
        "environments/azure/main.tf",
        "environments/gcp/main.tf",
        "modules/agent-identity/main.tf",
        "modules/ai-router/main.tf",
        "modules/audit/main.tf",
    ]:
        if not (tf_root / rel).exists():
            missing.append(f"terraform/{rel}")
    if missing:
        return Check("infra_readiness", False, f"Missing infra artifacts: {', '.join(missing)}")

    values = (helm_root / "values.yaml").read_text(encoding="utf-8", errors="ignore")
    helm_markers = ["resources:", "hpa:", "pdb:", "healthCheck:", "global:"]
    missing_helm_markers = [m for m in helm_markers if m not in values]

    prod = (tf_root / "environments/prod/main.tf").read_text(encoding="utf-8", errors="ignore").lower()
    azure = (tf_root / "environments/azure/main.tf").read_text(encoding="utf-8", errors="ignore").lower()
    gcp = (tf_root / "environments/gcp/main.tf").read_text(encoding="utf-8", errors="ignore").lower()
    tf_marker_gaps = []
    if "hashicorp/aws" not in prod:
        tf_marker_gaps.append("prod missing aws provider")
    if "hashicorp/azurerm" not in azure:
        tf_marker_gaps.append("azure missing azurerm provider")
    if "hashicorp/google" not in gcp:
        tf_marker_gaps.append("gcp missing google provider")

    if missing_helm_markers or tf_marker_gaps:
        details = []
        if missing_helm_markers:
            details.append(f"helm marker gaps: {', '.join(missing_helm_markers)}")
        if tf_marker_gaps:
            details.append(f"terraform marker gaps: {', '.join(tf_marker_gaps)}")
        return Check("infra_readiness", False, "; ".join(details))
    return Check("infra_readiness", True, "Helm hardening and Terraform multi-cloud environment artifacts validated")


def rasp_backcompat_check() -> Check:
    rasp = ROOT / "rasp"
    if not rasp.exists():
        return Check("rasp_backcompat_presence", False, "rasp directory missing")
    expected = ["python", "java", "go", "nodejs", "dotnet", "ruby", "php", "rust", "c_cpp"]
    missing = [lang for lang in expected if not (rasp / lang).exists()]
    if missing:
        return Check("rasp_backcompat_presence", False, f"Missing RASP dirs: {', '.join(missing)}")

    lacking_sources = []
    for lang in expected:
        lang_dir = rasp / lang
        count = 0
        for p in lang_dir.rglob("*"):
            if p.is_file() and p.suffix.lower() in {".py", ".java", ".go", ".js", ".ts", ".cs", ".rb", ".php", ".rs", ".c", ".cpp", ".h", ".hpp"}:
                count += 1
                if count >= 1:
                    break
        if count == 0:
            lacking_sources.append(lang)
    if lacking_sources:
        return Check("rasp_backcompat_presence", False, f"RASP source marker gaps: {', '.join(lacking_sources)}")

    langs = [p for p in rasp.iterdir() if p.is_dir()]
    if not langs:
        return Check("rasp_backcompat_presence", False, "No RASP subdirectories found")
    return Check("rasp_backcompat_presence", True, f"RASP subdirectories: {', '.join(sorted(p.name for p in langs))}")


def main() -> int:
    checks = []
    checks.append(
        exists_all(
            [
                ROOT / "infra/helm/cyberarmor/Chart.yaml",
                ROOT / "infra/terraform/modules/agent-identity/main.tf",
                ROOT / "infra/terraform/modules/ai-router/main.tf",
                ROOT / "infra/terraform/modules/audit/main.tf",
                ROOT / "scripts/smoke-test.sh",
                ROOT / "scripts/dashboard-integration-smoke.sh",
                ROOT / "scripts/dashboard-api-contract.sh",
            ],
            name="core_artifact_presence",
        )
    )
    checks.append(openapi_path_check())
    checks.append(openapi_core_service_parity_check())
    checks.append(service_contract_check())
    checks.append(sdk_surface_parity_check())
    checks.append(dashboard_presence_check())
    checks.append(infra_readiness_check())
    checks.append(rasp_backcompat_check())

    summary = {
        "root": str(ROOT),
        "passed": all(c.passed for c in checks),
        "checks": [asdict(c) for c in checks],
    }
    print(json.dumps(summary, indent=2))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
