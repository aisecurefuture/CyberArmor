#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_demo.sh"
require_cmd python3

TENANT_ID="${TENANT_ID:-default}"
ADMIN_KEY="${ADMIN_KEY:-$(load_env_var CYBERARMOR_API_SECRET change-me)}"

echo "== Demo 7: API Key Rotation + Blast Radius =="
echo "Tenant: $TENANT_ID"

wait_http "control-plane" "http://127.0.0.1:8000/health"

create_key() {
  local role="$1"
  curl -fsS -X POST "http://127.0.0.1:8000/apikeys" \
    -H "Content-Type: application/json" -H "x-api-key: ${ADMIN_KEY}" \
    -d '{"tenant_id":"'"$TENANT_ID"'","role":"'"$role"'"}'
}

KEY1_JSON="$(create_key analyst)"
KEY1="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("key",""))' <<<"$KEY1_JSON")"
[[ -n "$KEY1" ]] || { echo "failed to create key1" >&2; exit 1; }

PRE_CODE="$(curl -s -o /tmp/demo7_pre.json -w '%{http_code}' "http://127.0.0.1:8000/tenants" -H "x-api-key: ${KEY1}")"

curl -fsS -X PATCH "http://127.0.0.1:8000/apikeys/${KEY1}/disable" \
  -H "x-api-key: ${ADMIN_KEY}" >/dev/null

POST_CODE="$(curl -s -o /tmp/demo7_post.json -w '%{http_code}' "http://127.0.0.1:8000/tenants" -H "x-api-key: ${KEY1}")"

KEY2_JSON="$(create_key analyst)"
KEY2="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("key",""))' <<<"$KEY2_JSON")"
NEW_CODE="$(curl -s -o /tmp/demo7_new.json -w '%{http_code}' "http://127.0.0.1:8000/tenants" -H "x-api-key: ${KEY2}")"

echo "old key before disable: HTTP ${PRE_CODE}"
echo "old key after disable:  HTTP ${POST_CODE}"
echo "new replacement key:    HTTP ${NEW_CODE}"
echo "old key prefix: ${KEY1:0:8}..."
echo "new key prefix: ${KEY2:0:8}..."
echo "Dashboard: http://localhost:3000/#/api-keys"
