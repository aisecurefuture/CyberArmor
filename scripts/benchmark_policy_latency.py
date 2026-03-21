#!/usr/bin/env python3
"""Benchmark policy PDP latency and report p50/p95/p99."""

from __future__ import annotations

import argparse
import json
import os
import statistics
import time
import urllib.error
import urllib.request
from pathlib import Path


def load_env_value(env_path: Path, key: str, default: str) -> str:
    if not env_path.exists():
        return default
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == key:
            return v.strip()
    return default


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    idx = (len(values) - 1) * p
    lower = int(idx)
    upper = min(lower + 1, len(values) - 1)
    if lower == upper:
        return values[lower]
    weight = idx - lower
    return values[lower] * (1.0 - weight) + values[upper] * weight


def main() -> int:
    parser = argparse.ArgumentParser(description="Policy PDP latency benchmark")
    parser.add_argument("--base-url", default="http://localhost:8001")
    parser.add_argument("--tenant-id", default="smoke-tenant")
    parser.add_argument("--iterations", type=int, default=400)
    parser.add_argument("--warmup", type=int, default=50)
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    env_file = repo_root / "infra" / "docker-compose" / ".env"
    api_key = load_env_value(env_file, "POLICY_API_SECRET", "change-me-policy")

    payload = {
        "tenant_id": args.tenant_id,
        "context": {
            "request": {
                "host": "api.example.com",
                "method": "POST",
                "path": "/v1/chat/completions",
            }
        },
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }
    url = f"{args.base_url.rstrip('/')}/policies/evaluate"

    for _ in range(max(args.warmup, 0)):
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=args.timeout_seconds) as resp:
            if resp.status != 200:
                raise RuntimeError(f"warmup status={resp.status}")
            resp.read()

    durations_ms: list[float] = []
    started = time.perf_counter()
    for _ in range(args.iterations):
        t0 = time.perf_counter()
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=args.timeout_seconds) as resp:
            if resp.status != 200:
                raise RuntimeError(f"benchmark status={resp.status}")
            resp.read()
        durations_ms.append((time.perf_counter() - t0) * 1000.0)
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    durations_ms.sort()
    summary = {
        "endpoint": url,
        "iterations": args.iterations,
        "warmup": args.warmup,
        "avg_ms": round(statistics.fmean(durations_ms), 3),
        "min_ms": round(durations_ms[0], 3),
        "max_ms": round(durations_ms[-1], 3),
        "p50_ms": round(percentile(durations_ms, 0.50), 3),
        "p95_ms": round(percentile(durations_ms, 0.95), 3),
        "p99_ms": round(percentile(durations_ms, 0.99), 3),
        "throughput_rps": round((args.iterations * 1000.0) / elapsed_ms, 2),
        "target_p99_lt_5ms": True,
    }
    summary["target_met"] = summary["p99_ms"] < 5.0
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.HTTPError as exc:
        print(f"HTTP error: status={exc.code} reason={exc.reason}")
        raise SystemExit(1)
    except urllib.error.URLError as exc:
        print(f"URL error: {exc.reason}")
        raise SystemExit(1)
