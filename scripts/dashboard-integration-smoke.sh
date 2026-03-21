#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/infra/docker-compose/.env"

load_env_var() {
  local key="$1"
  local default_val="$2"
  if [[ -f "$ENV_FILE" ]]; then
    local val
    val="$(grep -E "^${key}=" "$ENV_FILE" | tail -n1 | cut -d'=' -f2- || true)"
    if [[ -n "$val" ]]; then
      echo "$val"
      return
    fi
  fi
  echo "$default_val"
}

wait_http() {
  local name="$1"
  local url="$2"
  local retries="${3:-60}"
  local delay="${4:-2}"
  for ((i=1; i<=retries; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "[OK] $name health: $url"
      return 0
    fi
    sleep "$delay"
  done
  echo "[FAIL] $name health timeout: $url" >&2
  return 1
}

ROUTER_API_KEY="$(load_env_var ROUTER_API_SECRET change-me-router)"
AGENT_IDENTITY_API_KEY="$(load_env_var AGENT_IDENTITY_API_SECRET change-me-agent-identity)"
AUDIT_API_KEY="$(load_env_var AUDIT_API_SECRET change-me-audit)"
TENANT_ID="${TENANT_ID:-smoke-tenant}"
TRACE_ID="trc_dashboard_${RANDOM}_$(date +%s)"

wait_http ai-router "http://localhost:8009/health"
wait_http agent-identity "http://localhost:8008/health"
wait_http audit "http://localhost:8011/health"
wait_http llm-mock "http://localhost:9000/health"

AGENT_JSON=$(curl -fsS \
  -X POST "http://localhost:8008/agents/register" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"name\":\"dashboard-smoke-agent\",\"display_name\":\"Dashboard Smoke Agent\",\"trust_level\":\"standard\",\"capabilities\":[\"ai:inference\"],\"allowed_tools\":[\"ai:inference\"]}")
AGENT_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("agent_id",""))' <<<"$AGENT_JSON")
if [[ -z "$AGENT_ID" ]]; then
  echo "[FAIL] register agent missing agent_id" >&2
  exit 1
fi
echo "[OK] agent registered: $AGENT_ID"

CONFIG_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "http://localhost:8009/credentials/providers/openai/configure?tenant_id=${TENANT_ID}" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${ROUTER_API_KEY}" \
  -d '{"api_key":"sk-mock","base_url":"http://llm-mock:9000/v1"}')
if [[ "$CONFIG_CODE" != "200" ]]; then
  echo "[FAIL] configure provider status: $CONFIG_CODE" >&2
  exit 1
fi
echo "[OK] provider configured for tenant ${TENANT_ID}"

CHAT_JSON=$(curl -fsS \
  -X POST "http://localhost:8009/ai/chat/completions" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${ROUTER_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"agent_id\":\"${AGENT_ID}\",\"trace_id\":\"${TRACE_ID}\",\"provider\":\"openai\",\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"dashboard integration smoke\"}]}")
if ! echo "$CHAT_JSON" | grep -q '"choices"'; then
  echo "[FAIL] ai chat response missing choices" >&2
  exit 1
fi
echo "[OK] ai test prompt executed via router"

TRACE_JSON="$(curl -fsS -X GET "http://localhost:8011/traces/${TRACE_ID}" -H "x-api-key: ${AUDIT_API_KEY}")"
TRACE_COUNT="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("span_count",0))' <<<"$TRACE_JSON")"
if [[ "$TRACE_COUNT" -lt 1 ]]; then
  echo "[FAIL] audit trace missing events for ${TRACE_ID}" >&2
  exit 1
fi
echo "[OK] audit trace contains ${TRACE_COUNT} event(s)"

GRAPH_JSON="$(curl -fsS -X GET "http://localhost:8011/graph/agent/${AGENT_ID}?hours=1" -H "x-api-key: ${AUDIT_API_KEY}")"
GRAPH_EVENTS="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("event_count",0))' <<<"$GRAPH_JSON")"
if [[ "$GRAPH_EVENTS" -lt 1 ]]; then
  echo "[FAIL] audit graph empty for agent ${AGENT_ID}" >&2
  exit 1
fi
echo "[OK] audit graph returned event_count=${GRAPH_EVENTS}"

echo "[PASS] Dashboard integration smoke completed successfully"
