# Integration Onboarding (Policy-Gated) Runbook

- Scope: onboarding SaaS and agentic-AI integrations through control-plane policy enforcement.
- Entry API: `POST /integrations/onboard` (control-plane).
- Dependent service: `integration-control` (`http://integration-control:8012`).

## Prerequisites

1. `control-plane` and `integration-control` services are running.
1. `INTEGRATION_CONTROL_API_SECRET` is set and aligned between services.
1. Caller has admin privileges in control-plane (`x-api-key` with admin role).

## Onboarding flow

1. Configure provider credentials/config in integration-control.
1. Run provider discovery to inventory connections/scopes/findings.
1. Evaluate integration policy (`allow|warn|block`).
1. Enable only if policy outcome permits.

## Control-plane endpoint

`POST /integrations/onboard`

Request body:

```json
{
  "provider": "microsoft365",
  "tenant_id": "default",
  "config": {},
  "include_events": true,
  "enforce_policy": true,
  "fail_on_warn": false
}
```

Behavior:

1. `action=block` -> returns `403` and does not enable onboarding.
1. `action=warn` + `fail_on_warn=true` -> returns `409`.
1. otherwise returns `status=enabled`.

## Provider examples

### Microsoft 365

```json
{
  "provider": "microsoft365",
  "tenant_id": "default",
  "config": {
    "client_id": "00000000-0000-0000-0000-000000000000",
    "client_secret": "redacted",
    "authority_tenant_id": "contoso.onmicrosoft.com"
  },
  "include_events": true,
  "enforce_policy": true
}
```

### Google Workspace

```json
{
  "provider": "google_workspace",
  "tenant_id": "default",
  "config": {
    "access_token": "ya29.redacted",
    "customer_id": "my_customer",
    "admin_email": "admin@example.com"
  },
  "include_events": true,
  "enforce_policy": true
}
```

### Salesforce

```json
{
  "provider": "salesforce",
  "tenant_id": "default",
  "config": {
    "instance_url": "https://your-org.my.salesforce.com",
    "access_token": "00Dxx0000000000!redacted"
  },
  "include_events": true,
  "enforce_policy": true
}
```

### Agentic AI inventory (OpenAI/Claude/Codex/Desktop-style)

```json
{
  "provider": "agentic_ai",
  "tenant_id": "default",
  "config": {
    "platform": "openai_codex",
    "source": "manual_inventory",
    "inventory": [
      {
        "app": "OpenAI Codex",
        "id": "codex-prod-01",
        "owner": "platform-security@example.com",
        "status": "active",
        "last_used_days": 2,
        "scopes": [
          "repo:read",
          "drive.readwrite"
        ],
        "connectors": [
          "github",
          "google_drive"
        ]
      }
    ]
  },
  "include_events": true,
  "enforce_policy": true
}
```

## Post-onboarding checks

1. Query `GET /integrations/findings` for new high/medium findings.
1. Query `GET /integrations/permissions?risk_level=high` to verify high-risk grants.
1. If needed, run control actions:
1. revoke consent: `POST /integrations/providers/{provider}/consents/{consent_id}/revoke`
1. disable connection: `POST /integrations/providers/{provider}/connections/{connection_id}/disable`

## Policy tuning

Environment in `integration-control`:

1. `INTEGRATION_POLICY_BLOCK_HIGH_RISK_SCOPE`
1. `INTEGRATION_POLICY_BLOCK_UNOWNED`
1. `INTEGRATION_POLICY_BLOCK_STALE_ACTIVE`
1. `INTEGRATION_POLICY_STALE_DAYS`

Recommended production baseline:

1. block high-risk scopes = `true`
1. block unowned integrations = `true`
1. block stale active integrations = `true`
1. stale threshold = `30` (adjust by risk tolerance)

