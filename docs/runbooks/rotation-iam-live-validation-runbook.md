# Rotation IAM Live Validation Runbook

- Scope: validate effective least-privilege posture for production rotation identities.
- Workflow: `.github/workflows/ci-security-iam-live-validation.yml`
- Evidence artifact: `security-rotation-iam-live-evidence`

## Purpose

1. Confirm required rotation permissions are effectively allowed for the active identity.
1. Confirm sensitive over-privileged actions are not effectively allowed.
1. Preserve machine-readable evidence for security review and audit.

## Inputs

1. `provider` (`aws|azure|gcp`)
1. Provider-specific identity reference:
1. AWS: `aws_role_arn` (role used by rotation workflow)
1. Azure: `azure_role_name` (custom role name bound to rotation principal)
1. GCP: `gcp_role_id` (`projects/<project>/roles/<role>` or org role id)

## Execution

1. Trigger the workflow with `workflow_dispatch`.
1. Select `provider` and fill provider-specific input.
1. Wait for job completion.
1. Download and archive `security-rotation-iam-live-evidence`.

## Validation logic

1. AWS: uses `iam simulate-principal-policy` for required secret-manager actions and verifies prohibited actions are not allowed.
1. Azure: inspects live role definition actions and verifies required actions exist with no wildcard `*`.
1. GCP: inspects live custom role included permissions and verifies required permissions exist with no wildcard `*`.

## Operational guidance

1. Run before and after IAM changes affecting rotation identities.
1. Run as part of quarterly access reviews.
1. Attach evidence artifact to security review records.
