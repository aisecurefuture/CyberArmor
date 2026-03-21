# Dashboard Integration Smoke Report

- Date: 2026-03-08
- Command: `bash scripts/dashboard-integration-smoke.sh`
- Scope:
  - Register agent
  - Configure provider credential
  - Execute test prompt through router
  - Verify audit trace event
  - Verify audit graph response

## Result

- Status: `PASS`
- Key output:
  - `[OK] agent registered: agt_167843e207d24ab48985`
  - `[OK] provider configured for tenant smoke-tenant`
  - `[OK] ai test prompt executed via router`
  - `[OK] audit trace contains 1 event(s)`
  - `[OK] audit graph returned event_count=1`
  - `[PASS] Dashboard integration smoke completed successfully`

## Artifacts Added

1. `scripts/dashboard-integration-smoke.sh`
1. `services/ai-router/main.py` (audit event emission for router calls)
