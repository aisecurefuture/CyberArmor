#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_demo.sh"
require_cmd python3

TENANT_ID="${TENANT_ID:-default}"
POLICY_KEY="${POLICY_KEY:-$(load_env_var POLICY_API_SECRET change-me-policy)}"
TS="$(date +%s)"
POL_NAME="demo-require-approval-${TS}"

echo "== Demo 2: Human In The Loop Approval =="
echo "Tenant: $TENANT_ID"

wait_http "policy" "http://127.0.0.1:8001/health"

curl -fsS -X POST "http://127.0.0.1:8001/policies" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${POLICY_KEY}" \
  -d '{"tenant_id":"'"$TENANT_ID"'","name":"'"$POL_NAME"'","description":"Require approval for high-risk transfer endpoint","action":"warn","priority":5,"enabled":true,"tags":["demo","approval"],"conditions":{"operator":"AND","rules":[{"field":"request.url","operator":"contains","value":"/sensitive-approval-demo"}]},"rules":{}}' >/dev/null

MATCH_JSON="$(curl -fsS -X POST "http://127.0.0.1:8001/policies/${TENANT_ID}/evaluate" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${POLICY_KEY}" \
  -d '{"context":{"request":{"url":"https://api.vendor.com/sensitive-approval-demo"}}}')"
MISS_JSON="$(curl -fsS -X POST "http://127.0.0.1:8001/policies/${TENANT_ID}/evaluate" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${POLICY_KEY}" \
  -d '{"context":{"request":{"url":"https://api.vendor.com/normal-endpoint"}}}')"

python3 - "$MATCH_JSON" "$MISS_JSON" <<'PY'
import json, sys
hit = json.loads(sys.argv[1])
miss = json.loads(sys.argv[2])
print(f"matched endpoint decision: {hit.get('decision')} policy={hit.get('policy_name')}")
print(f"normal endpoint decision:  {miss.get('decision')} policy={miss.get('policy_name')}")
PY

echo "Dashboard: http://localhost:3000/#/policy-studio"
