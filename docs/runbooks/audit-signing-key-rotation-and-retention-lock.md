# Audit Signing-Key Rotation and Retention Lock Runbook

- Scope: `services/audit`
- Goals:
1. Maintain append-only tamper-evident audit integrity.
1. Rotate signing keys without breaking verification continuity.
1. Enforce minimum immutable retention windows.

## Required environment controls

1. `CYBERARMOR_AUDIT_SIGNING_KEY` (active key material)
1. `CYBERARMOR_AUDIT_SIGNING_KEY_ID` (active key id, example `k1`)
1. `CYBERARMOR_AUDIT_NEXT_SIGNING_KEY` (optional staged next key)
1. `CYBERARMOR_AUDIT_NEXT_SIGNING_KEY_ID` (staged next key id)
1. `CYBERARMOR_ENFORCE_IMMUTABLE_RETENTION=true`
1. `AUDIT_RETENTION_DAYS` (must be `>= AUDIT_MIN_RETENTION_DAYS`)
1. `AUDIT_MIN_RETENTION_DAYS` (organizational floor)

## Rotation model

1. Stage next key:
1. Set `CYBERARMOR_AUDIT_NEXT_SIGNING_KEY` and `CYBERARMOR_AUDIT_NEXT_SIGNING_KEY_ID`.
1. Verify status endpoint reflects staged key:
1. `GET /integrity/signing-key/status`

1. Cut over active key:
1. Promote next key to active:
1. set `CYBERARMOR_AUDIT_SIGNING_KEY=<next>`
1. set `CYBERARMOR_AUDIT_SIGNING_KEY_ID=<next-id>`
1. Optionally keep prior key as new `CYBERARMOR_AUDIT_NEXT_SIGNING_KEY` during grace period.

1. Validate continuity:
1. Ingest a new event.
1. Verify:
1. new events sign with new key id
1. prior events still verify during grace period.

1. Retire prior key:
1. Remove staged prior key after verification window closes.

## Retention lock policy

1. Set immutable retention enforcement:
1. `CYBERARMOR_ENFORCE_IMMUTABLE_RETENTION=true`
1. Guarantee:
1. startup fails if `AUDIT_RETENTION_DAYS < AUDIT_MIN_RETENTION_DAYS`
1. prevents accidental low-retention deployment drift.

## Operational checks

1. CI static gates:
1. `scripts/security/check_audit_immutability_policy.py`
1. `scripts/phase2_gap_audit.py`

1. API checks:
1. `GET /integrity/signing-key/status`
1. `GET /integrity/verify/{event_id}`

## Incident response

1. On key compromise suspicion:
1. immediately stage and promote a new signing key id
1. snapshot and preserve affected evidence window
1. perform targeted integrity verification sweep on critical traces
1. file incident with affected key ids and timestamp bounds.
