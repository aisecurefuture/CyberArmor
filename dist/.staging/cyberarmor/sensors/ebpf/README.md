# Unified eBPF AI Telemetry Sensor (moat)

Goal: **kernel-level visibility for AI usage** that feeds the platform telemetry pipeline.

## Why this matters
- Detects *unknown AI tools* (zero-day tooling) by observing outbound connections at the kernel level.
- Correlates network activity with process metadata (binary path, user, container).
- Provides defensible differentiation: **"kernel to cloud"** claim is real.

## What is included (starter kit)
- `ai_telemetry.bt` — a bpftrace script that logs outbound TCP connects with process + destination.
- `exporter.py` — parses stdout and emits JSON lines (ready to be ingested by control-plane telemetry endpoint).

## Run locally (Linux)
Requirements: bpftrace + kernel headers.

```bash
sudo bpftrace sensors/ebpf/ai_telemetry.bt | python3 sensors/ebpf/exporter.py
```

## Next step (production)
Replace bpftrace with a libbpf CO-RE program + Go/Rust collector that exports OTLP.
