#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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

AGENT_IDENTITY_API_KEY="$(load_env_var AGENT_IDENTITY_API_SECRET change-me-agent-identity)"
TENANT_A="${TENANT_A:-tenant-neg-a}"
TENANT_B="${TENANT_B:-tenant-neg-b}"

wait_http agent-identity "http://127.0.0.1:8008/health"

echo "[STEP] register tenant A and tenant B agents"
A_JSON=$(curl -fsS \
  -X POST "http://127.0.0.1:8008/agents/register" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_A}\",\"name\":\"neg-agent-a-${RANDOM}\",\"display_name\":\"Tenant A Agent\",\"trust_level\":\"standard\",\"capabilities\":[\"ai:inference\"],\"allowed_tools\":[\"ai:inference\"]}")
A_AGENT_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("agent_id",""))' <<<"$A_JSON")
if [[ -z "$A_AGENT_ID" ]]; then
  echo "[FAIL] failed to create tenant A agent" >&2
  exit 1
fi

B_JSON=$(curl -fsS \
  -X POST "http://127.0.0.1:8008/agents/register" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_B}\",\"name\":\"neg-agent-b-${RANDOM}\",\"display_name\":\"Tenant B Agent\",\"trust_level\":\"standard\",\"capabilities\":[\"ai:inference\"],\"allowed_tools\":[\"ai:inference\"]}")
B_AGENT_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("agent_id",""))' <<<"$B_JSON")
if [[ -z "$B_AGENT_ID" ]]; then
  echo "[FAIL] failed to create tenant B agent" >&2
  exit 1
fi

echo "[STEP] deny cross-tenant token issue"
ISSUE_CODE=$(curl -s -o /tmp/tenant_neg_issue.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:8008/agents/${A_AGENT_ID}/tokens/issue" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_B}\",\"scopes\":[\"ai:inference\"],\"expires_in\":3600}")
if [[ "$ISSUE_CODE" != "403" && "$ISSUE_CODE" != "404" ]]; then
  echo "[FAIL] cross-tenant issue unexpectedly allowed (status=$ISSUE_CODE)" >&2
  cat /tmp/tenant_neg_issue.json >&2 || true
  exit 1
fi
echo "[OK] cross-tenant token issue denied"

echo "[STEP] verify tenant-B list does not include tenant-A agent"
LIST_B=$(curl -fsS "http://127.0.0.1:8008/agents?tenant_id=${TENANT_B}&limit=500" -H "x-api-key: ${AGENT_IDENTITY_API_KEY}")
python3 -c 'import json,sys; aid=sys.argv[1]; obj=json.loads(sys.stdin.read()); arr=obj if isinstance(obj,list) else obj.get("agents",[]); leak=any((a.get("agent_id")==aid) for a in arr if isinstance(a,dict)); raise SystemExit(1 if leak else 0)' "$A_AGENT_ID" <<<"$LIST_B"
echo "[OK] no tenant-A data leakage in tenant-B list"

echo "[PASS] Tenant isolation negative checks passed"
