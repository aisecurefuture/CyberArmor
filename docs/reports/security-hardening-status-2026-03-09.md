# Security Hardening Status

- Date: 2026-03-09
- Repo: `<repo-root>`

## Implemented in this pass

1. CI security hardening gate
   - Added `security-hardening` job in:
     - `.github/workflows/ci-core.yml`
   - Enforces:
     - `python3 scripts/security/check_sensitive_logging.py`
     - `python3 scripts/phase2_gap_audit.py`

1. Sensitive logging static check
   - Added:
     - `scripts/security/check_sensitive_logging.py`
   - Behavior:
     - scans Python service logging calls for likely secret/token logging patterns
     - fails CI on high-risk patterns

1. Tenant isolation negative tests
   - Added:
     - `scripts/security/tenant-isolation-negative.sh`
   - Added to heavy smoke workflow:
     - `.github/workflows/ci-heavy-smoke.yml`
   - Asserts:
     - cross-tenant token issue is denied
     - tenant-B list does not leak tenant-A agent identity

1. Strict secret startup enforcement for core services
   - Added strict-mode startup refusal for insecure default secrets in:
     - `services/control-plane/main.py`
     - `services/agent-identity/main.py`
     - `services/ai-router/main.py`
     - `services/policy/main.py`
     - `services/audit/main.py`
     - `services/identity/main.py`
     - `services/detection/main.py`
     - `services/siem-connector/main.py`
   - Behavior:
     - `CYBERARMOR_ENFORCE_SECURE_SECRETS=true` enables strict checks.
     - `CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true` allows explicit dev override.
     - In strict mode without override, startup fails if key secrets are unset or use `change-me*` placeholders.

1. Environment template hardening controls
   - Updated:
     - `infra/docker-compose/.env.example`
   - Added:
     - `CYBERARMOR_ENFORCE_SECURE_SECRETS`
     - `CYBERARMOR_ALLOW_INSECURE_DEFAULTS`
   - Included guidance for production vs local development use.

1. mTLS baseline readiness enforcement
   - Added mTLS startup config checks to core services:
     - `services/control-plane/main.py`
     - `services/policy/main.py`
     - `services/agent-identity/main.py`
     - `services/ai-router/main.py`
     - `services/audit/main.py`
   - Behavior:
     - `CYBERARMOR_ENFORCE_MTLS=true` requires:
       - `CYBERARMOR_TLS_CA_FILE`
       - `CYBERARMOR_TLS_CERT_FILE`
       - `CYBERARMOR_TLS_KEY_FILE`
     - startup fails if required TLS artifacts are unset or missing.
   - Docker compose baseline:
     - mounted shared read-only cert volume into the same core services:
       - `certs:/etc/cyberarmor/tls:ro`
   - Added static readiness check:
     - `scripts/security/check_mtls_readiness.py`
   - Added CI gate:
     - `.github/workflows/ci-core.yml` now runs the mTLS readiness check.

1. mTLS transport enforcement (first implementation slice)
   - Enforced HTTPS upstream requirement when `CYBERARMOR_ENFORCE_MTLS=true` in:
     - `services/ai-router/main.py` for internal audit emission
     - `services/runtime/main.py` for detection/policy/response/compliance/control-plane calls
   - Enforced client-cert outbound calls under mTLS mode for the above service-to-service HTTP clients.
   - Extended compose cert-mount baseline to runtime:
     - `infra/docker-compose/docker-compose.yml` now mounts `certs:/etc/cyberarmor/tls:ro` on runtime.
   - Extended static mTLS readiness check coverage to runtime:
     - `scripts/security/check_mtls_readiness.py`

1. mTLS transport enforcement (expanded to proxy paths)
   - Enforced HTTPS upstream requirement under `CYBERARMOR_ENFORCE_MTLS=true` in:
     - `services/proxy/transparent_proxy.py` (runtime/policy/detection/telemetry upstreams)
     - `services/proxy/ai_interceptor.py` (detection/telemetry upstreams)
     - `agents/proxy-agent/main.py` (policy upstream)
   - Enforced client-cert outbound calls under mTLS mode in those components.
   - Extended compose cert mounts to:
     - `proxy-agent`
     - `transparent-proxy` (additional `/etc/cyberarmor/tls` mount)
   - Extended static mTLS readiness coverage to:
     - `proxy-agent`
     - `transparent-proxy`

1. Native server-side TLS listener baseline
   - Added shared TLS-aware uvicorn launcher:
     - `scripts/security/run_uvicorn_tls.py`
   - Core service/agent Dockerfiles now use launcher:
     - `services/control-plane/Dockerfile`
     - `services/policy/Dockerfile`
     - `services/agent-identity/Dockerfile`
     - `services/ai-router/Dockerfile`
     - `services/audit/Dockerfile`
     - `services/runtime/Dockerfile`
     - `agents/proxy-agent/Dockerfile`
   - Added listener controls in env template:
     - `CYBERARMOR_ENABLE_NATIVE_TLS_LISTENER`
     - `CYBERARMOR_REQUIRE_CLIENT_CERT`
   - Added CI policy check:
     - `scripts/security/check_native_tls_listener_policy.py`
     - wired in `.github/workflows/ci-core.yml`

1. Gateway/listener-side mTLS policy enforcement baseline
   - Helm ingress mTLS policy controls added:
     - `infra/helm/cyberarmor/values.yaml` (`ingress.mtls.*`)
     - `infra/helm/cyberarmor/templates/ingress.yaml` (nginx auth-tls annotations when enabled)
   - Added static policy gate:
     - `scripts/security/check_gateway_mtls_policy.py`
   - Added CI enforcement:
     - `.github/workflows/ci-core.yml` now runs gateway mTLS policy check.

1. Certificate rotation runbook
   - Added operational runbook:
     - `docs/runbooks/mtls-certificate-rotation-runbook.md`
   - Covers overlap CA strategy, staged secret rollout, validation, and emergency rollback.

1. Audit immutability and signing-key rotation enforcement
   - Audit service enforcement added in:
     - `services/audit/main.py`
   - Controls added:
     - key-id aware signatures (`CYBERARMOR_AUDIT_SIGNING_KEY_ID`)
     - staged next-key verification support (`CYBERARMOR_AUDIT_NEXT_SIGNING_KEY`, `..._ID`)
     - immutable retention guard (`CYBERARMOR_ENFORCE_IMMUTABLE_RETENTION`, `AUDIT_RETENTION_DAYS`, `AUDIT_MIN_RETENTION_DAYS`)
     - signing key status endpoint:
       - `GET /integrity/signing-key/status`
   - CI static gate added:
     - `scripts/security/check_audit_immutability_policy.py`
     - wired in `.github/workflows/ci-core.yml`
   - Operational runbook added:
     - `docs/runbooks/audit-signing-key-rotation-and-retention-lock.md`

1. Rotation execution pipeline automation baseline
   - Added executable rotation tooling:
     - `scripts/security/generate_mtls_materials.sh`
     - `scripts/security/rotate_audit_signing_key.py`
   - Added rotation drill workflow:
     - `.github/workflows/ci-security-rotation-drill.yml`
     - runs weekly + on-demand (`workflow_dispatch`)
     - validates cert generation and audit key rotation dry-run path
   - Added core CI static gate:
     - `scripts/security/check_rotation_pipeline.py`
     - wired in `.github/workflows/ci-core.yml`

1. Production-style secret-manager-backed rotation pipeline with approvals
   - Added provider-aware rotation execution helper:
     - `scripts/security/rotate_secrets_with_manager.py`
   - Added approval-gated workflow:
     - `.github/workflows/ci-security-rotation-approval.yml`
     - uses `workflow_dispatch`
     - enforces `environment: security-approval`
     - requires `SECURITY_ROTATION_APPROVAL_TOKEN` for apply mode
   - Added policy gate:
     - `scripts/security/check_secret_manager_rotation_policy.py`
     - wired in `.github/workflows/ci-core.yml`
   - Added runbook:
     - `docs/runbooks/secret-manager-rotation-approval-runbook.md`
   - Added execution evidence artifact flow:
     - workflow writes and uploads `security-rotation-evidence` artifact
     - rotation script emits structured evidence JSON via `--artifact-file`
   - Added stricter policy checks to require evidence artifact wiring.
   - Added operation semantics:
     - `rotate`, `promote`, `rollback`
     - provider version-targeting ref support for promote/rollback paths.
   - Added workload identity/OIDC auth wiring in approval workflow:
     - AWS `configure-aws-credentials`
     - Azure `login`
     - GCP `google-github-actions/auth`
   - Added signed approval metadata in rotation evidence:
     - evidence includes `approval.signature` (HMAC over approval metadata in apply mode)
   - Change-ticket linkage is optional:
     - workflow `change_ticket` input is optional and can be included for evidence metadata when available.

1. Rotation IAM least-privilege policy baseline and static enforcement
   - Added provider policy templates:
     - `infra/security/iam/aws-rotation-policy.json`
     - `infra/security/iam/azure-rotation-role.json`
     - `infra/security/iam/gcp-rotation-role.yaml`
   - Added static gate:
     - `scripts/security/check_rotation_iam_least_privilege.py`
   - Added CI enforcement:
     - `.github/workflows/ci-core.yml` now runs rotation IAM least-privilege policy check.

1. Live cloud IAM least-privilege validation and evidence workflow
   - Added provider-aware live IAM validation script:
     - `scripts/security/validate_rotation_iam_live.py`
   - Added OIDC-enabled on-demand workflow:
     - `.github/workflows/ci-security-iam-live-validation.yml`
   - Added runbook:
     - `docs/runbooks/rotation-iam-live-validation-runbook.md`
   - Enhanced static IAM gate to enforce presence/wiring of live validation assets:
     - `scripts/security/check_rotation_iam_least_privilege.py`

1. Authorization negative matrix coverage
   - Added:
     - `scripts/security/authz-negative-matrix.sh`
   - Added to heavy smoke workflow:
     - `.github/workflows/ci-heavy-smoke.yml`
   - Asserts unauthenticated requests are denied (`401/403`) for:
     - agent identity protected routes
     - policy protected routes
     - AI router protected routes
     - audit protected routes
     - identity protected routes
     - detection protected routes
     - SIEM ingest protected route
   - Additional coverage:
     - role-based deny (analyst blocked from control-plane admin endpoint)
     - cross-tenant deny (control-plane telemetry ingest rejects tenant scope mismatch)
   - Expanded endpoint depth:
     - agent identity token/delegation/workload protected routes
     - policy evaluate/batch/import/simulate/explain protected routes
     - ai-router chat/models/credential management protected routes
     - audit graph/timeline/export/integrity protected routes
     - control-plane admin role-restricted routes (`/tenants`, `/apikeys`, `/audit/logs`)
   - Added positive authorization checks:
     - admin role allowed on control-plane admin routes (non-`401/403`):
       - `GET /tenants`
       - `GET /apikeys`
       - `GET /audit/logs`
     - tenant-matched analyst ingestion allowed (non-`401/403`) on:
       - `POST /telemetry/ingest` with matching `x-tenant-id` and payload `tenant_id`.

1. Dependency and container vulnerability CI gates
   - Added workflow:
     - `.github/workflows/ci-security-vuln.yml`
   - Enforced scanners:
     - Python: `pip-audit` across service/SDK requirements
     - Node: `npm audit --audit-level=high`
     - Go: `govulncheck` for `sdks/go` and `rasp/go`
     - Container image: Trivy scan of `ai-router` image
   - Fail-threshold policy:
     - dependency vulnerabilities fail build
     - container scan fails on `HIGH,CRITICAL` findings

## Remaining high-priority hardening (production)

1. None currently tracked in this phase; continue periodic operational validation and evidence collection.
