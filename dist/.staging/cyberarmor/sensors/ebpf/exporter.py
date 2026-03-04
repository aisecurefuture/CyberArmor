#!/usr/bin/env python3
"""Parse bpftrace output and emit JSON lines for ingestion.

This is intentionally minimal: it demonstrates the telemetry path without requiring
OTLP wiring on day 1.

Usage:
  sudo bpftrace sensors/ebpf/ai_telemetry.bt | python3 sensors/ebpf/exporter.py
"""

import json
import os
import sys
import time


def enrich(pid: int) -> dict:
    base = {"pid": pid}
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
        base["cmdline"] = cmd
    except Exception:
        pass
    try:
        base["exe"] = os.readlink(f"/proc/{pid}/exe")
    except Exception:
        pass
    return base


for line in sys.stdin:
    line = line.strip()
    if not line.startswith("CONNECT "):
        continue
    parts = dict(p.split("=", 1) for p in line.replace("CONNECT ", "").split() if "=" in p)
    try:
        pid = int(parts.get("pid", "0"))
    except Exception:
        pid = 0

    evt = {
        "ts": time.time(),
        "event": "connect",
        "comm": parts.get("comm"),
        **enrich(pid),
    }
    print(json.dumps(evt), flush=True)
