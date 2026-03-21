#!/usr/bin/env python3
import re
import sys
from pathlib import Path

import yaml


ROUTE_RE = re.compile(r'@app\.(get|post|put|patch|delete|api_route)\(\s*["\']([^"\']+)["\']')
SKIP_PATHS = {"/docs", "/openapi.json", "/v1/chat/completions"}
SKIP_PREFIXES = ("/health", "/ready", "/metrics")


def _collect_service_paths(repo_root: Path) -> set[str]:
    paths: set[str] = set()
    for main_py in (repo_root / "services").glob("*/main.py"):
        text = main_py.read_text(encoding="utf-8")
        for _, path in ROUTE_RE.findall(text):
            if path in SKIP_PATHS:
                continue
            if path.startswith(SKIP_PREFIXES):
                continue
            paths.add(path)
    return paths


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    spec_path = repo_root / "docs" / "api" / "openapi.yaml"
    with spec_path.open("r", encoding="utf-8") as f:
        spec = yaml.safe_load(f)
    openapi_paths = set((spec.get("paths") or {}).keys())
    service_paths = _collect_service_paths(repo_root)
    missing = sorted(p for p in service_paths if p not in openapi_paths)
    if missing:
        print("OPENAPI_DRIFT_DETECTED: undocumented service paths found:")
        for p in missing:
            print(f" - {p}")
        return 1
    print("OPENAPI_DRIFT_CHECK_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
