# Phase 2 Deliverables Status (Codex)

- Date: 2026-03-08
- Repository: `<repo-root>`

## High-Priority Gaps

1. Admin dashboard <-> agent-identity mismatch: `Completed`
1. Policy API required endpoints + decision model: `Completed`
1. AI router API surface + provider connector abstraction: `Completed`
1. Credential durability/security (Postgres + AES-256-GCM + tenant scope): `Completed`
1. Audit append-only + tamper/signature integrity: `Completed`
1. Health/readiness/metrics consistency across services: `Completed`

## Testing Evidence (latest)

1. Smoke E2E:
   - Command: `bash scripts/smoke-test.sh --up`
   - Status: `PASS`
   - Covers:
     - service health checks (`/health`, `/ready` paths in stack startup order)
     - tenant create, policy upsert/evaluate
     - policy decision matrix: `DENY`, `ALLOW_WITH_REDACTION`, `ALLOW_WITH_LIMITS`, `REQUIRE_APPROVAL`, `ALLOW_WITH_AUDIT_ONLY`, `QUARANTINE`
     - ext_authz call path
     - detection + SIEM ingest
     - agent register -> token issue -> validate -> revoke
     - audit ingest -> integrity verification

1. PDP performance:
   - Command: `python3 scripts/benchmark_policy_latency.py --iterations 500 --warmup 60`
   - Report: `docs/reports/pdp-latency-report-2026-03-08.md`
   - Result: `p99=3.251ms` (`PASS`, target `<5ms`)

## Remaining Work (Spec-Scale, Non-Blocking to current smoke path)

1. Full line-by-line checklist mapping for all items in `AI-Identity-Control-Plane-Build-Prompt.md` (all sections, not only high-priority gaps).
1. Expanded dashboard integration automation (UI test suite for register/configure/prompt/audit graph render path).
1. Cross-language SDK parity audit and missing behavior tests for all language targets.
1. Framework integration parity verification (LangChain, LlamaIndex, Vercel AI, native OpenAI/Anthropic adapters) with dedicated tests.
1. Infra completeness verification for Helm/Terraform modules across target clouds and environments.
1. Final acceptance package (single consolidated report with file-by-file mapping + commands + outputs).

## Runbook

1. Start stack:
   - `bash scripts/smoke-test.sh --up`
1. Seed/validate baseline data:
   - Included in smoke flow (tenant create + policy create + registration + audit ingest)
1. Run E2E:
   - `bash scripts/smoke-test.sh --up`
1. Run PDP benchmark:
   - `python3 scripts/benchmark_policy_latency.py --iterations 500 --warmup 60`
1. Manual endpoint checks:
   - `curl -fsS http://localhost:8000/health`
   - `curl -fsS http://localhost:8001/health`
   - `curl -fsS http://localhost:8009/health`
   - `curl -fsS http://localhost:8011/health`
