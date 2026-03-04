# CyberArmor.ai Policy Engine

Extensible policy evaluation engine with support for nested AND/OR condition groups, priority-based rule matching, and configurable enforcement actions.

## Features

- **AND/OR Condition Groups**: Nested boolean logic for complex policy rules
- **15+ Operators**: equals, not_equals, contains, regex, gt, lt, gte, lte, in, not_in, starts_with, ends_with, exists, not_exists, between
- **Priority-Based Evaluation**: Policies evaluated in priority order (lower = higher priority)
- **Action Modes**: monitor (log only), warn (alert + allow), block (deny), allow (explicit permit)
- **Multi-Tenant**: Tenant-scoped policy sets
- **Hot Reload**: Policy changes effective immediately

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/policies` | Create a new policy |
| GET | `/policies/{tenant_id}` | List all policies for a tenant |
| GET | `/policies/{tenant_id}/{name}` | Get policy details |
| PUT | `/policies/{id}` | Update a policy |
| DELETE | `/policies/{id}` | Delete a policy |
| POST | `/evaluate` | Evaluate a request against all active policies |
| GET | `/proxy-mode/{tenant_id}` | Resolve tenant runtime mode (`mitm` or `envoy`) |
| * | `/ext_authz/check` | Envoy external auth endpoint |
| GET | `/health` | Health check |

## Policy Structure

```json
{
  "name": "Block PII to External AI",
  "tenant_id": "tenant-1",
  "priority": 10,
  "enabled": true,
  "action": "block",
  "conditions": {
    "operator": "AND",
    "conditions": [
      {
        "field": "destination",
        "operator": "contains",
        "value": "openai.com"
      },
      {
        "operator": "OR",
        "conditions": [
          {"field": "content", "operator": "regex", "value": "\\b\\d{3}-\\d{2}-\\d{4}\\b"},
          {"field": "content", "operator": "regex", "value": "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"},
          {"field": "classification", "operator": "in", "value": ["CONFIDENTIAL", "RESTRICTED"]}
        ]
      }
    ]
  }
}
```

## Running

```bash
pip install fastapi uvicorn sqlalchemy
uvicorn main:app --host 0.0.0.0 --port 8001
```

## Evaluation Example

```bash
curl -X POST http://localhost:8001/evaluate \
  -H "x-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-1",
    "request": {
      "destination": "api.openai.com",
      "content": "Process this SSN: 123-45-6789",
      "user": "user@company.com",
      "model": "gpt-4"
    }
  }'
```

Response:
```json
{
  "decision": "block",
  "matched_policy": "Block PII to External AI",
  "policy_id": "policy-uuid",
  "reason": "Content contains sensitive PII pattern (SSN)"
}
```
