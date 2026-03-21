#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_demo.sh"
require_cmd python3

TENANT_A="${TENANT_A:-demo-tenant-a-$(date +%s)}"
TENANT_B="${TENANT_B:-demo-tenant-b-$(date +%s)}"
AGENT_KEY="${AGENT_KEY:-$(load_env_var AGENT_IDENTITY_API_SECRET change-me-agent-identity)}"

echo "== Demo 4: Tenant Isolation =="
echo "tenant A: $TENANT_A"
echo "tenant B: $TENANT_B"

wait_http "agent-identity" "http://127.0.0.1:8008/health"

A_JSON="$(curl -fsS -X POST "http://127.0.0.1:8008/agents/register" \
  -H "Content-Type: application/json" -H "x-api-key: ${AGENT_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_A}\",\"name\":\"iso-a-${RANDOM}\",\"display_name\":\"Isolation A\",\"capabilities\":[\"ai:inference\"]}")"
A_AGENT_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("agent_id",""))' <<<"$A_JSON")"

B_JSON="$(curl -fsS -X POST "http://127.0.0.1:8008/agents/register" \
  -H "Content-Type: application/json" -H "x-api-key: ${AGENT_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_B}\",\"name\":\"iso-b-${RANDOM}\",\"display_name\":\"Isolation B\",\"capabilities\":[\"ai:inference\"]}")"
B_AGENT_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("agent_id",""))' <<<"$B_JSON")"

LIST_A="$(curl -fsS "http://127.0.0.1:8008/agents?tenant_id=${TENANT_A}&limit=500" -H "x-api-key: ${AGENT_KEY}")"
LIST_B="$(curl -fsS "http://127.0.0.1:8008/agents?tenant_id=${TENANT_B}&limit=500" -H "x-api-key: ${AGENT_KEY}")"

python3 - "$LIST_A" "$LIST_B" "$A_AGENT_ID" "$B_AGENT_ID" <<'PY'
import json, sys
la = json.loads(sys.argv[1]); lb = json.loads(sys.argv[2])
a_id = sys.argv[3]; b_id = sys.argv[4]
arr_a = la if isinstance(la, list) else la.get("agents", [])
arr_b = lb if isinstance(lb, list) else lb.get("agents", [])
in_a = any((x.get("agent_id") == a_id) for x in arr_a if isinstance(x, dict))
in_b = any((x.get("agent_id") == b_id) for x in arr_b if isinstance(x, dict))
leak_a_in_b = any((x.get("agent_id") == a_id) for x in arr_b if isinstance(x, dict))
leak_b_in_a = any((x.get("agent_id") == b_id) for x in arr_a if isinstance(x, dict))
print(f"tenant A contains A agent: {in_a}")
print(f"tenant B contains B agent: {in_b}")
print(f"cross-tenant leakage A->B: {leak_a_in_b}")
print(f"cross-tenant leakage B->A: {leak_b_in_a}")
if not (in_a and in_b) or leak_a_in_b or leak_b_in_a:
    raise SystemExit(1)
PY

echo "isolation check: PASS"
