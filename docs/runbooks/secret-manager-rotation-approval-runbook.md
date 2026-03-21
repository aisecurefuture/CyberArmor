# Secret Manager Rotation Approval Runbook

- Scope: production secret rotation execution using provider secret managers
- Workflow: `.github/workflows/ci-security-rotation-approval.yml`

## Providers supported

1. AWS Secrets Manager
1. Azure Key Vault
1. GCP Secret Manager

## Approval model

1. Rotation execution is only triggered via `workflow_dispatch`.
1. The workflow job runs in `environment: security-approval`.
1. Workflow uses OIDC/workload identity federation (`id-token: write`) for cloud authentication.
1. Apply mode requires:
1. protected environment approval
1. `SECURITY_ROTATION_APPROVAL_TOKEN` secret
1. matching approval token validation in the rotation script

## Usage

1. Dry run:
1. trigger workflow with:
1. `apply=false`
1. provider (`aws|azure|gcp`)
1. operation (`rotate|promote|rollback`)
1. item refs (JSON list or comma-separated refs)
1. optional `change_ticket` value for evidence metadata

1. Apply run:
1. trigger workflow with `apply=true`
1. choose operation (`rotate|promote|rollback`)
1. optionally provide `change_ticket` (not required)
1. wait for required environment approval
1. confirm rotation execution logs include:
1. `SECRET_MANAGER_ROTATION_APPLY`
1. `ROTATION_EXECUTION_OK`
1. download and archive workflow artifact:
1. `security-rotation-evidence`

## Rotation item format

1. JSON list example:
1. `[{"name":"audit_signing_key","ref":"cyberarmor/prod/audit/signing-key"}]`

1. Comma-separated example:
1. `cyberarmor/prod/audit/signing-key,cyberarmor/prod/router/encryption-key`

1. Versioned refs for promote/rollback:
1. AWS: `<secret-id>@<version-id>`
1. Azure: `<vault-name>/<secret-name>@<version-id>`
1. GCP: `projects/<project>/secrets/<secret>@<version>`

## Security requirements

1. Never commit approval tokens or rotated secret values.
1. Require two-person review for apply runs.
1. Record ticket/change id in workflow notes when available (recommended, optional).
1. Verify post-rotation integrity endpoints and health checks.
1. Store rotation evidence artifact with change-management record.
1. Verify evidence includes signed approval metadata (`approval.signature`).
