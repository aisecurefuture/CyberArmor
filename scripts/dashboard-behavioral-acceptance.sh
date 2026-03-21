#!/usr/bin/env bash
set -euo pipefail

# Note: this script is a behavioral smoke test.
# For strict payload schema assertions used by dashboard views, run:
#   bash scripts/dashboard-api-contract.sh

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
POLICY_API_KEY="$(load_env_var POLICY_API_SECRET change-me-policy)"
TENANT_ID="${TENANT_ID:-dashboard-acceptance-tenant}"
TRACE_ID="trc_dashboard_accept_${RANDOM}_$(date +%s)"

wait_http ai-router "http://127.0.0.1:8009/health"
wait_http agent-identity "http://127.0.0.1:8008/health"
wait_http audit "http://127.0.0.1:8011/health"
wait_http policy "http://127.0.0.1:8001/health"
wait_http llm-mock "http://127.0.0.1:9000/health"

echo "[STEP] agents view backing flow"
AGENT_JSON=$(curl -fsS \
  -X POST "http://127.0.0.1:8008/agents/register" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"name\":\"acceptance-agent\",\"display_name\":\"Acceptance Agent\",\"trust_level\":\"standard\",\"capabilities\":[\"ai:inference\"],\"allowed_tools\":[\"ai:inference\"]}")
AGENT_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("agent_id",""))' <<<"$AGENT_JSON")
if [[ -z "$AGENT_ID" ]]; then
  echo "[FAIL] missing agent_id on register" >&2
  exit 1
fi
LIST_JSON=$(curl -fsS "http://127.0.0.1:8008/agents?tenant_id=${TENANT_ID}&limit=200" -H "x-api-key: ${AGENT_IDENTITY_API_KEY}")
python3 -c 'import json,sys; aid=sys.argv[1]; obj=json.loads(sys.stdin.read()); arr=obj if isinstance(obj,list) else obj.get("agents",[]); ok=any((a.get("agent_id")==aid) for a in arr if isinstance(a,dict)); raise SystemExit(0 if ok else 1)' "$AGENT_ID" <<<"$LIST_JSON"
TOKEN_JSON=$(curl -fsS -X POST "http://127.0.0.1:8008/agents/${AGENT_ID}/tokens/issue" \
  -H "Content-Type: application/json" -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"scopes\":[\"ai:inference\"],\"expires_in\":3600}")
TOKEN_VALUE=$(python3 -c 'import json,sys; o=json.loads(sys.stdin.read()); print(o.get("access_token") or o.get("token") or "")' <<<"$TOKEN_JSON")
if [[ -z "$TOKEN_VALUE" ]]; then
  echo "[FAIL] missing token value" >&2
  exit 1
fi
echo "[OK] agents register/list/issue-token flow"

echo "[STEP] providers view backing flow"
curl -fsS -X POST "http://127.0.0.1:8009/credentials/providers/openai/configure?tenant_id=${TENANT_ID}" \
  -H "Content-Type: application/json" -H "x-api-key: ${ROUTER_API_KEY}" \
  -d '{"api_key":"sk-mock","base_url":"http://llm-mock:9000/v1","default_model":"gpt-4o-mini"}' >/dev/null
PROVIDERS_JSON=$(curl -fsS "http://127.0.0.1:8009/ai/providers" -H "x-api-key: ${ROUTER_API_KEY}")
python3 -c 'import json,sys; obj=json.loads(sys.stdin.read()); arr=obj.get("providers",[]) if isinstance(obj,dict) else (obj if isinstance(obj,list) else []); ok=any((p.get("id")=="openai" or p.get("provider")=="openai" or p.get("provider_id")=="openai") for p in arr if isinstance(p,dict)); raise SystemExit(0 if ok else 1)' <<<"$PROVIDERS_JSON"
echo "[OK] provider configure/list flow"

echo "[STEP] policy-studio view backing flow"
POL_LIST=$(curl -fsS "http://127.0.0.1:8001/policies/${TENANT_ID}" -H "x-api-key: ${POLICY_API_KEY}")
python3 -c 'import json,sys; obj=json.loads(sys.stdin.read()); raise SystemExit(0 if isinstance(obj,list) else 1)' <<<"$POL_LIST"
POL_EVAL_CODE=$(curl -s -o /tmp/dashboard_policy_eval.json -w '%{http_code}' \
  -X POST "http://127.0.0.1:8001/policies/${TENANT_ID}/evaluate" \
  -H "Content-Type: application/json" -H "x-api-key: ${POLICY_API_KEY}" \
  -d '{"policy_name":"default","context":{"provider":"openai","model":"gpt-4o-mini","prompt":"test","tenant_id":"'"${TENANT_ID}"'"}}')
if [[ "$POL_EVAL_CODE" != "200" && "$POL_EVAL_CODE" != "404" ]]; then
  echo "[FAIL] policy evaluate unexpected status: $POL_EVAL_CODE" >&2
  exit 1
fi
echo "[OK] policy list/evaluate endpoint behavior"

echo "[STEP] graph + risk view backing flow"
CHAT_JSON=$(curl -fsS -X POST "http://127.0.0.1:8009/ai/chat/completions" \
  -H "Content-Type: application/json" -H "x-api-key: ${ROUTER_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"agent_id\":\"${AGENT_ID}\",\"trace_id\":\"${TRACE_ID}\",\"provider\":\"openai\",\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"behavioral acceptance test\"}]}")
if ! echo "$CHAT_JSON" | grep -q '"choices"'; then
  echo "[FAIL] router completion missing choices" >&2
  exit 1
fi
GRAPH_JSON=$(curl -fsS "http://127.0.0.1:8011/graph/agent/${AGENT_ID}?hours=1" -H "x-api-key: ${AUDIT_API_KEY}")
python3 -c 'import json,sys; obj=json.loads(sys.stdin.read()); ec=int(obj.get("event_count",0)) if isinstance(obj,dict) else 0; raise SystemExit(0 if ec>=1 else 1)' <<<"$GRAPH_JSON"
EVENTS_JSON=$(curl -fsS "http://127.0.0.1:8011/events?tenant_id=${TENANT_ID}&limit=200" -H "x-api-key: ${AUDIT_API_KEY}")
python3 -c 'import json,sys; obj=json.loads(sys.stdin.read()); arr=obj if isinstance(obj,list) else obj.get("events",[]); raise SystemExit(0 if isinstance(arr,list) else 1)' <<<"$EVENTS_JSON"
echo "[OK] graph/risk data endpoints"

echo "[STEP] delegations view backing flow"
DELEGATE_JSON=$(curl -fsS \
  -X POST "http://127.0.0.1:8008/agents/register" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"name\":\"acceptance-delegate\",\"display_name\":\"Acceptance Delegate\",\"trust_level\":\"standard\",\"capabilities\":[\"ai:inference\"],\"allowed_tools\":[\"ai:inference\"]}")
DELEGATE_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("agent_id",""))' <<<"$DELEGATE_JSON")
if [[ -z "$DELEGATE_ID" ]]; then
  echo "[FAIL] missing delegate agent_id" >&2
  exit 1
fi
EXP_AT=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc)+timedelta(hours=1)).isoformat())')
DEL_CREATE=$(curl -fsS -X POST "http://127.0.0.1:8008/delegations" \
  -H "Content-Type: application/json" -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" \
  -d "{\"parent_human_id\":\"human-acceptance\",\"agent_id\":\"${DELEGATE_ID}\",\"scope\":[\"ai:inference\"],\"expires_at\":\"${EXP_AT}\"}")
CHAIN_ID=$(python3 -c 'import json,sys; o=json.loads(sys.stdin.read()); print(o.get("chain_id") or o.get("id") or "")' <<<"$DEL_CREATE")
if [[ -z "$CHAIN_ID" ]]; then
  echo "[FAIL] missing delegation chain id" >&2
  exit 1
fi
DEL_LIST=$(curl -fsS "http://127.0.0.1:8008/delegations?limit=200" -H "x-api-key: ${AGENT_IDENTITY_API_KEY}")
python3 -c 'import json,sys; cid=sys.argv[1]; obj=json.loads(sys.stdin.read()); arr=obj if isinstance(obj,list) else obj.get("delegations",[]); ok=any((d.get("chain_id")==cid or d.get("id")==cid) for d in arr if isinstance(d,dict)); raise SystemExit(0 if ok else 1)' "$CHAIN_ID" <<<"$DEL_LIST"
curl -fsS -X DELETE "http://127.0.0.1:8008/delegations/${CHAIN_ID}" -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" >/dev/null
echo "[OK] delegation create/list/revoke flow"

echo "[STEP] onboarding view backing content"
ONBOARD_COUNT=$(python3 - <<'PY'
from pathlib import Path
text=Path("admin-dashboard/app.js").read_text(encoding="utf-8", errors="ignore")
need=["pip install cyberarmor-sdk","npm install @cyberarmor/sdk","go get github.com/cyberarmor-ai/cyberarmor-go","dotnet add package CyberArmor.SDK","composer require cyberarmor/sdk","cargo add cyberarmor-sdk"]
print(sum(1 for n in need if n in text))
PY
)
if [[ "$ONBOARD_COUNT" -lt 6 ]]; then
  echo "[FAIL] onboarding content incomplete: matched $ONBOARD_COUNT/6 install snippets" >&2
  exit 1
fi
echo "[OK] onboarding content present"

echo "[PASS] Dashboard behavioral acceptance checks passed"
