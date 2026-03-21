# mTLS Certificate Rotation Runbook

- Scope: CyberArmor control-plane and proxy inter-service trust chain
- Environment: Kubernetes deployments using `infra/helm/cyberarmor`

## Rotation policy

1. Server TLS cert validity: 90 days max.
1. Client mTLS cert validity: 30 days max.
1. Rotation trigger:
1. scheduled at 2/3 lifetime, or
1. emergency rotation on key compromise/suspected compromise.
1. CA strategy:
1. maintain active + next CA overlap window during cutover.
1. retire old CA only after all workloads are rotated and verified.

## Prerequisites

1. Existing ingress TLS secret (`ingress.tls.secretName`).
1. Existing client CA secret (`ingress.mtls.caSecretName`).
1. New server cert/key and new client cert/key artifacts prepared.
1. Access to deployment namespace and secret-management workflow.

## Rotation steps

1. Generate new cert material.
1. Issue new server cert and client certs from approved CA.
1. Record serial numbers and not-after dates.

1. Stage secrets.
1. Create new Kubernetes TLS secrets for server and client credentials.
1. If rotating CA, stage a bundle containing both old and new CA during overlap.

1. Update Helm values/references.
1. Ensure ingress TLS secret reference points to new server cert secret.
1. Ensure `ingress.mtls.caSecretName` points to bundled CA during overlap.
1. Ensure workloads mount updated client cert/key files at:
1. `/etc/cyberarmor/tls/ca.crt`
1. `/etc/cyberarmor/tls/tls.crt`
1. `/etc/cyberarmor/tls/tls.key`

1. Rollout.
1. Deploy chart update.
1. Restart workloads that cache TLS contexts.
1. Verify health/readiness and mTLS-authenticated inter-service traffic.

1. Validate and cutover.
1. Confirm no services present expired/old certs.
1. Remove old CA from trust bundle after validation window.
1. Revoke old certs where revocation is available.

## Verification checklist

1. Ingress enforces mTLS (`auth-tls-verify-client: on`).
1. Internal client calls succeed with `CYBERARMOR_ENFORCE_MTLS=true`.
1. No service falls back to plaintext `http://` internal upstreams.
1. CI gates pass:
1. `scripts/security/check_mtls_readiness.py`
1. `scripts/security/check_gateway_mtls_policy.py`

## Emergency rollback

1. Repoint secrets to last-known-good certs.
1. Re-deploy workloads.
1. Keep compromised certs revoked and open incident with audit trace IDs.
