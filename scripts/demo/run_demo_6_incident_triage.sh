#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_demo.sh"
require_cmd python3

TENANT_ID="${TENANT_ID:-default}"
CP_KEY="${CP_KEY:-$(load_env_var CYBERARMOR_API_SECRET change-me)}"
TS="$(date +%s)"

echo "== Demo 6: Incident Triage =="
echo "Tenant: $TENANT_ID"

wait_http "control-plane" "http://127.0.0.1:8000/health"

post_incident() {
  local req_id="$1"
  local decision="$2"
  local reason="$3"
  curl -fsS -X POST "http://127.0.0.1:8000/incidents/ingest" \
    -H "Content-Type: application/json" \
    -H "x-api-key: ${CP_KEY}" \
    -d '{"tenant_id":"'"$TENANT_ID"'","request_id":"'"$req_id"'","event_type":"triage_demo","decision":"'"$decision"'","reasons":["'"$reason"'"],"metadata":{"source":"demo6"}}' >/dev/null
}

RID_BLOCK="triage-block-${TS}"
RID_WARN="triage-warn-${TS}"
RID_ALLOW="triage-allow-${TS}"

post_incident "$RID_BLOCK" "block" "prompt_injection_detected"
post_incident "$RID_WARN" "warn" "pii_detected"
post_incident "$RID_ALLOW" "allow" "benign"

LIST_JSON="$(curl -fsS "http://127.0.0.1:8000/incidents/${TENANT_ID}?limit=20" -H "x-api-key: ${CP_KEY}")"
python3 - "$LIST_JSON" <<'PY'
import json, sys
arr = json.loads(sys.argv[1])
counts = {"block":0,"warn":0,"allow":0,"other":0}
for i in arr:
    d = str(i.get("decision", "other")).lower()
    if d in counts:
        counts[d] += 1
    else:
        counts["other"] += 1
print(f"incidents listed: {len(arr)}")
print(f"block={counts['block']} warn={counts['warn']} allow={counts['allow']} other={counts['other']}")
PY

echo "request_ids: $RID_BLOCK, $RID_WARN, $RID_ALLOW"
echo "Dashboard: http://localhost:3000/#/incidents"
