# CyberArmor Integration Control Service

Canonical integration discovery and control plane for SaaS/agentic AI app integrations.

## Implemented providers (phase 1)

1. Microsoft 365 (`microsoft365`)
1. Google Workspace (`google_workspace`)
1. Salesforce (`salesforce`)
1. Agentic AI platforms (`agentic_ai`) via normalized inventory ingest
1. Discovery coverage:
1. service principals (app connections)
1. OAuth2 permission grants (granted scopes)
1. high-risk scope findings
1. Google token scope inventory and Google Drive exposure findings
1. Salesforce connected app inventory and OAuth scope/policy findings
1. Agentic AI integration inventory (OpenAI/Claude/Codex/Desktop-style), scope risking, ownership/staleness findings
1. Control actions:
1. revoke OAuth consent grant
1. disable service principal connection
1. revoke Google OAuth token (disable app connection may require admin-console manual step)
1. revoke Salesforce OAuth token (connected-app disable may require admin policy action)
1. manual-action control responses for agentic AI platform integrations (revoke/disable paths tracked)

## API endpoints

1. `GET /health`
1. `GET /ready`
1. `GET /metrics`
1. `GET /integrations/providers`
1. `POST /integrations/providers/microsoft365/configure`
1. `POST /integrations/providers/google-workspace/configure`
1. `POST /integrations/providers/salesforce/configure`
1. `POST /integrations/providers/agentic-ai/configure`
1. `POST /integrations/discovery/run`
1. `GET /integrations/connections`
1. `GET /integrations/permissions`
1. `GET /integrations/findings`
1. `POST /integrations/policy/evaluate`
1. `POST /integrations/providers/{provider}/consents/{consent_id}/revoke`
1. `POST /integrations/providers/{provider}/connections/{connection_id}/disable`

## Canonical model

1. `IntegrationProvider`
1. `IntegrationConnection`
1. `IntegrationPermission`
1. `IntegrationEvent`
1. `IntegrationFinding`

## Runbooks

1. `docs/runbooks/integration-onboarding-policy-gated-runbook.md`

## CI gate

1. `scripts/security/check_integration_control_policy.py`
1. `.github/workflows/ci-integration-control.yml`

## Run locally

```bash
pip install fastapi uvicorn[standard] pydantic httpx
uvicorn main:app --host 0.0.0.0 --port 8012
```

## Environment

1. `INTEGRATION_CONTROL_API_SECRET` (default `change-me-integration-control`)
1. `CYBERARMOR_ENFORCE_SECURE_SECRETS`
1. `CYBERARMOR_ALLOW_INSECURE_DEFAULTS`
1. `INTEGRATION_POLICY_BLOCK_HIGH_RISK_SCOPE` (default `true`)
1. `INTEGRATION_POLICY_BLOCK_UNOWNED` (default `true`)
1. `INTEGRATION_POLICY_BLOCK_STALE_ACTIVE` (default `false`)
1. `INTEGRATION_POLICY_STALE_DAYS` (default `30`)
