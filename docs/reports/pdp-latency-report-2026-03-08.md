# PDP Latency Report

- Date: 2026-03-08
- Service: `policy`
- Endpoint: `POST /policies/evaluate` (`http://localhost:8001/policies/evaluate`)
- Command:
  - `python3 scripts/benchmark_policy_latency.py --iterations 500 --warmup 60`

## Result Summary

- Iterations: `500` (plus `60` warmup)
- Average: `1.532 ms`
- Min: `1.144 ms`
- Max: `5.049 ms`
- p50: `1.428 ms`
- p95: `2.202 ms`
- p99: `3.251 ms`
- Throughput: `652.51 req/s`

## Acceptance Check

- Target: `p99 < 5 ms`
- Observed: `p99 = 3.251 ms`
- Status: `PASS`
