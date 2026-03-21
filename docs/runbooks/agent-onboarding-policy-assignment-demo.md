# Agent Onboarding + Policy Assignment Demo (10 min)

## Goal

Show a complete flow where an AI agent is onboarded, receives credentials, gets a policy assigned, and policy evaluation enforces different outcomes for assigned vs non-assigned agents.

## Prerequisites

1. Docker Desktop running.
1. Services available on localhost (`8008` agent identity, `8001` policy, `3000` dashboard).
1. API keys present in `infra/docker-compose/.env`.

## One-command setup

```bash
bash scripts/demo/run_agent_policy_demo.sh --build --no-cache
```

For faster reruns without rebuilding:

```bash
bash scripts/demo/run_agent_policy_demo.sh --seed-only
```

## Suggested presenter flow

1. Start in terminal and run `bash scripts/demo/run_agent_policy_demo.sh --seed-only`.
1. Call out the printed IDs:
   - `tenant_id`
   - `agent_id`
   - `policy_id`
1. Highlight verification output:
   - assigned agent -> `decision: DENY`
   - other agent -> `decision: ALLOW`
1. Open [http://localhost:3000/#/agents](http://localhost:3000/#/agents) and show the onboarded agent.
1. Open [http://localhost:3000/#/policies](http://localhost:3000/#/policies) and show the policy name tied to the demo agent.
1. Open [http://localhost:3000/#/policy-studio](http://localhost:3000/#/policy-studio) and explain decision outcomes.
1. Optional: open [http://localhost:3000/#/policy-builder](http://localhost:3000/#/policy-builder) to show how conditions map to `metadata.agent_id` and `request.url`.

## Talking points

1. Onboarding is explicit and auditable (`POST /agents/register`).
1. Credentials are scoped and short-lived (`POST /agents/{id}/tokens/issue`).
1. Policy assignment is deterministic by context match (example: `metadata.agent_id == <agent_id>`).
1. Enforcement is testable before production traffic (`POST /policies/{tenant}/evaluate`).

## API proof snippets

Register an agent:

```bash
curl -X POST http://localhost:8008/agents/register \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: <AGENT_IDENTITY_API_SECRET>' \
  -d '{"tenant_id":"default","name":"sales-assistant","display_name":"sales-assistant"}'
```

Assign a policy to that agent:

```bash
curl -X POST http://localhost:8001/policies \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: <POLICY_API_SECRET>' \
  -d '{"tenant_id":"default","name":"block-sales-assistant-openai","action":"block","conditions":{"operator":"AND","rules":[{"field":"metadata.agent_id","operator":"equals","value":"<agent_id>"},{"field":"request.url","operator":"contains","value":"openai.com/v1/chat/completions"}]}}'
```

Evaluate enforcement result:

```bash
curl -X POST http://localhost:8001/policies/default/evaluate \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: <POLICY_API_SECRET>' \
  -d '{"context":{"request":{"url":"https://api.openai.com/v1/chat/completions"},"metadata":{"agent_id":"<agent_id>"}}}'
```
