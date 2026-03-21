# Dashboard Behavioral Acceptance Report

- Date: 2026-03-09
- Repo root: `<repo-root>`
- Scope: AI Identity dashboard views (`agents`, `providers`, `policy-studio`, `graph`, `risk`, `delegations`, `onboarding`)

## Command run

```bash
bash scripts/dashboard-behavioral-acceptance.sh
```

## Result

- Status: `PASS`
- Output summary:
  - agent register/list/issue-token flow passed
  - provider configure/list flow passed
  - policy list/evaluate endpoint behavior passed
  - graph/risk data endpoints passed
  - delegation create/list/revoke flow passed
  - onboarding content checks passed

## Compatibility fixes added in this pass

1. Policy dashboard compatibility endpoint:
   - Added `POST /policies/{tenant_id}/evaluate` alias in:
     - `services/policy/main.py`
2. Dashboard acceptance runner:
   - Added:
     - `scripts/dashboard-behavioral-acceptance.sh`
   - Script uses direct service contracts and validates all 7 AI Identity view backing behaviors.

## Notes

- Script is intended to run against the local compose stack.
- If services are not running, start with:
  - `bash scripts/smoke-test.sh --up`
