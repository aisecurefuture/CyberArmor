#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_demo.sh"
require_cmd python3

TENANT_ID="${TENANT_ID:-default}"
AGENT_KEY="${AGENT_KEY:-$(load_env_var AGENT_IDENTITY_API_SECRET change-me-agent-identity)}"
TS="$(date +%s)"

echo "== Demo 3: Delegation Chain =="
echo "Tenant: $TENANT_ID"

wait_http "agent-identity" "http://127.0.0.1:8008/health"

AGENT_JSON="$(curl -fsS -X POST "http://127.0.0.1:8008/agents/register" \
  -H "Content-Type: application/json" -H "x-api-key: ${AGENT_KEY}" \
  -d '{"tenant_id":"'"$TENANT_ID"'","name":"delegate-agent-'"$TS"'","display_name":"delegate-agent-'"$TS"'","capabilities":["ai:inference"],"allowed_tools":["ai:inference"]}')"
AGENT_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("agent_id",""))' <<<"$AGENT_JSON")"
[[ -n "$AGENT_ID" ]] || { echo "agent register failed" >&2; exit 1; }

EXP_AT="$(python3 -c 'from datetime import datetime,timedelta,timezone; print((datetime.now(timezone.utc)+timedelta(hours=1)).isoformat())')"
DEL_JSON="$(curl -fsS -X POST "http://127.0.0.1:8008/delegations" \
  -H "Content-Type: application/json" -H "x-api-key: ${AGENT_KEY}" \
  -d '{"parent_human_id":"human-demo-owner","agent_id":"'"$AGENT_ID"'","scope":["ai:inference"],"expires_at":"'"$EXP_AT"'"}')"
CHAIN_ID="$(python3 -c 'import json,sys; o=json.loads(sys.stdin.read()); print(o.get("chain_id") or o.get("id") or "")' <<<"$DEL_JSON")"
[[ -n "$CHAIN_ID" ]] || { echo "delegation create failed" >&2; exit 1; }

TOKEN_JSON="$(curl -fsS -X POST "http://127.0.0.1:8008/agents/${AGENT_ID}/tokens/issue" \
  -H "Content-Type: application/json" -H "x-api-key: ${AGENT_KEY}" \
  -d '{"tenant_id":"'"$TENANT_ID"'","scopes":["ai:inference"],"expires_in":1800}')"
TOKEN_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("token_id",""))' <<<"$TOKEN_JSON")"

LIST_JSON="$(curl -fsS "http://127.0.0.1:8008/delegations?tenant_id=${TENANT_ID}&limit=200" -H "x-api-key: ${AGENT_KEY}")"
HAS_CHAIN="$(python3 - "$LIST_JSON" "$CHAIN_ID" <<'PY'
import json, sys
obj = json.loads(sys.argv[1]); cid = sys.argv[2]
arr = obj if isinstance(obj, list) else obj.get("delegations", [])
print("yes" if any((d.get("chain_id") == cid or d.get("id") == cid) for d in arr if isinstance(d, dict)) else "no")
PY
)"

curl -fsS -X DELETE "http://127.0.0.1:8008/delegations/${CHAIN_ID}" -H "x-api-key: ${AGENT_KEY}" >/dev/null

echo "agent_id:   $AGENT_ID"
echo "chain_id:   $CHAIN_ID (present in list: $HAS_CHAIN)"
echo "token_id:   ${TOKEN_ID:-n/a}"
echo "revocation: complete"
echo "Dashboard:  http://localhost:3000/#/delegations"
