#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_demo.sh"
require_cmd python3

TENANT_ID="${TENANT_ID:-default}"
COMP_KEY="${COMP_KEY:-$(load_env_var COMPLIANCE_API_SECRET change-me-compliance)}"
CP_KEY="${CP_KEY:-$(load_env_var CYBERARMOR_API_SECRET change-me)}"
REQ_ID="compliance-demo-$(date +%s)"

echo "== Demo 8: Compliance Evidence -> Report =="
echo "Tenant: $TENANT_ID"
echo "Request ID: $REQ_ID"

wait_http "compliance" "http://127.0.0.1:8006/health"
wait_http "control-plane" "http://127.0.0.1:8000/health"

curl -fsS -X POST "http://127.0.0.1:8006/evidence/${TENANT_ID}/${REQ_ID}" \
  -H "Content-Type: application/json" -H "x-api-key: ${COMP_KEY}" \
  -d '{"evidence":{"identity_management":true,"mfa_enabled":true,"audit_logging_enabled":true,"incident_response_plan":true,"least_privilege_enforced":true,"key_rotation_enabled":true}}' >/dev/null

ASSESS_JSON="$(curl -fsS -X POST "http://127.0.0.1:8006/assess/${TENANT_ID}/${REQ_ID}" \
  -H "Content-Type: application/json" -H "x-api-key: ${COMP_KEY}" \
  -d '{"framework":"soc2"}')"

curl -fsS -X POST "http://127.0.0.1:8000/incidents/ingest" \
  -H "Content-Type: application/json" -H "x-api-key: ${CP_KEY}" \
  -d '{"tenant_id":"'"$TENANT_ID"'","request_id":"'"$REQ_ID"'","event_type":"compliance_report_generated","decision":"allow","reasons":["evidence_assessed"],"metadata":{"source":"demo8"}}' >/dev/null

python3 - "$ASSESS_JSON" <<'PY'
import json, sys
o = json.loads(sys.argv[1])
score = o.get("score_pct", o.get("overall_score", "n/a"))
fw = o.get("framework_id", "soc2")
status = o.get("status", "computed")
print(f"framework={fw} score={score} status={status}")
PY

echo "Evidence JSON:  http://localhost:8006/evidence/${TENANT_ID}/${REQ_ID}"
echo "Report JSON:    http://localhost:8006/assess/${TENANT_ID}/${REQ_ID}/report"
echo "Viewer page:    http://localhost:8000/viewer/${TENANT_ID}/${REQ_ID}"
