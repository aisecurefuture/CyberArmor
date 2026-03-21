#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_demo.sh"
require_cmd python3

TENANT_ID="${TENANT_ID:-default}"
CP_KEY="${CP_KEY:-$(load_env_var CYBERARMOR_API_SECRET change-me)}"
if [[ "$TENANT_ID" == "default" ]]; then
  TENANT_ID="provider-gov-$(date +%s)"
fi
RISKY_TENANT="${TENANT_ID}-risky"
SAFE_TENANT="${TENANT_ID}-safe"

echo "== Demo 5: Provider Governance =="
echo "Risky tenant: $RISKY_TENANT"
echo "Safe tenant:  $SAFE_TENANT"

wait_http "control-plane" "http://127.0.0.1:8000/health"
wait_http "integration-control" "http://127.0.0.1:8012/health"

RISKY_BODY='{"provider":"agentic_ai","tenant_id":"'"$RISKY_TENANT"'","config":{"platform":"openai_codex","source":"manual_inventory","inventory":[{"app":"Codex Risky","id":"codex-risky-1","status":"active","last_used_days":120,"scopes":["drive.readwrite","mail.readwrite"],"connectors":["google_drive"]}]},"include_events":true,"enforce_policy":true,"fail_on_warn":true}'
SAFE_BODY='{"provider":"agentic_ai","tenant_id":"'"$SAFE_TENANT"'","config":{"platform":"openai_codex","source":"manual_inventory","inventory":[{"app":"Codex Safe","id":"codex-safe-1","owner":"platform-security@example.com","status":"active","last_used_days":2,"scopes":["repo:read"],"connectors":["github"]}]},"include_events":true,"enforce_policy":true,"fail_on_warn":true}'

RISKY_CODE="$(curl -s -o /tmp/demo5_risky.json -w '%{http_code}' -X POST "http://127.0.0.1:8000/integrations/onboard" \
  -H "Content-Type: application/json" -H "x-api-key: ${CP_KEY}" -d "$RISKY_BODY")"
SAFE_CODE="$(curl -s -o /tmp/demo5_safe.json -w '%{http_code}' -X POST "http://127.0.0.1:8000/integrations/onboard" \
  -H "Content-Type: application/json" -H "x-api-key: ${CP_KEY}" -d "$SAFE_BODY")"

echo "risky onboarding status: $RISKY_CODE (expect 403/409)"
echo "safe onboarding status:  $SAFE_CODE (expect 200)"

python3 - <<'PY'
import json
from pathlib import Path
for name in ["risky", "safe"]:
    p = Path(f"/tmp/demo5_{name}.json")
    if not p.exists():
        continue
    try:
        o = json.loads(p.read_text())
    except Exception:
        print(f"{name}: non-json response")
        continue
    if isinstance(o, dict):
        detail = o.get("detail")
        if isinstance(detail, dict):
            pol = detail.get("policy", {})
            print(f"{name}: action={pol.get('action')} reason={pol.get('reason')}")
        else:
            pol = o.get("policy", {})
            print(f"{name}: action={pol.get('action')} reason={pol.get('reason')}")
PY

echo "Runbook: $ROOT_DIR/docs/runbooks/integration-onboarding-policy-gated-runbook.md"
