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

assert_json_contract() {
  local file="$1"
  local check="$2"
  python3 - "$file" "$check" <<'PY'
import json
import sys

path = sys.argv[1]
check = sys.argv[2]
obj = json.loads(open(path, "r", encoding="utf-8").read() or "null")

def fail(msg: str):
    print(f"[FAIL] {check}: {msg}", file=sys.stderr)
    raise SystemExit(1)

def as_list(v):
    if isinstance(v, list):
        return v
    return []

if check == "tenants":
    if not isinstance(obj, list):
        fail("expected list")
    for t in obj:
        if not isinstance(t, dict):
            fail("tenant item must be object")
        tid = t.get("tenant_id") or t.get("id")
        if tid is not None and not isinstance(tid, str):
            fail("tenant_id/id must be string")
elif check == "policies":
    if not isinstance(obj, list):
        fail("expected list")
    for p in obj:
        if not isinstance(p, dict):
            fail("policy item must be object")
        if "action" in p and not isinstance(p.get("action"), str):
            fail("policy action must be string")
elif check == "agents":
    arr = obj if isinstance(obj, list) else obj.get("agents", [])
    if not isinstance(arr, list):
        fail("expected list or {agents:list}")
    for a in arr:
        if not isinstance(a, dict):
            fail("agent item must be object")
        aid = a.get("agent_id") or a.get("id")
        if aid is not None and not isinstance(aid, str):
            fail("agent id must be string")
elif check == "providers":
    arr = obj if isinstance(obj, list) else obj.get("providers", [])
    if not isinstance(arr, list):
        fail("expected list or {providers:list}")
    for p in arr:
        if not isinstance(p, dict):
            fail("provider item must be object")
elif check == "events":
    arr = obj if isinstance(obj, list) else obj.get("events", [])
    if not isinstance(arr, list):
        fail("expected list or {events:list}")
    for e in arr:
        if not isinstance(e, dict):
            fail("event item must be object")
        if "action" in e and e["action"] is not None and not isinstance(e["action"], str):
            fail("event action must be string when present")
        for k in ("risk_score",):
            if k in e and e[k] is not None and not isinstance(e[k], (int, float)):
                fail(f"{k} must be numeric when present")
elif check == "graph":
    if not isinstance(obj, dict):
        fail("expected object")
    if "event_count" in obj and not isinstance(obj.get("event_count"), int):
        fail("event_count must be integer")
    if "edges" in obj and not isinstance(obj.get("edges"), list):
        fail("edges must be list")
elif check == "delegations":
    arr = obj if isinstance(obj, list) else obj.get("delegations", [])
    if not isinstance(arr, list):
        fail("expected list or {delegations:list}")
    for d in arr:
        if not isinstance(d, dict):
            fail("delegation item must be object")
        cid = d.get("chain_id") or d.get("id")
        if cid is not None and not isinstance(cid, str):
            fail("chain_id/id must be string")
else:
    fail(f"unknown check: {check}")

print(f"[OK] {check} contract")
PY
}

ROUTER_API_KEY="$(load_env_var ROUTER_API_SECRET change-me-router)"
AGENT_IDENTITY_API_KEY="$(load_env_var AGENT_IDENTITY_API_SECRET change-me-agent-identity)"
AUDIT_API_KEY="$(load_env_var AUDIT_API_SECRET change-me-audit)"
POLICY_API_KEY="$(load_env_var POLICY_API_SECRET change-me-policy)"
CP_API_KEY="$(load_env_var CONTROL_PLANE_API_SECRET "")"
if [[ -z "${CP_API_KEY}" ]]; then
  CP_API_KEY="$(load_env_var CYBERARMOR_API_SECRET "")"
fi
if [[ -z "${CP_API_KEY}" ]]; then
  CP_API_KEY="change-me"
fi
TENANT_ID="${TENANT_ID:-dashboard-contract-tenant}"

wait_http control-plane "http://127.0.0.1:8000/health"
wait_http policy "http://127.0.0.1:8001/health"
wait_http agent-identity "http://127.0.0.1:8008/health"
wait_http ai-router "http://127.0.0.1:8009/health"
wait_http audit "http://127.0.0.1:8011/health"

curl -fsS "http://127.0.0.1:8000/tenants" \
  -H "x-api-key: ${CP_API_KEY}" >/tmp/dashboard_contract_tenants.json
assert_json_contract /tmp/dashboard_contract_tenants.json tenants

curl -fsS "http://127.0.0.1:8001/policies/${TENANT_ID}" \
  -H "x-api-key: ${POLICY_API_KEY}" >/tmp/dashboard_contract_policies.json
assert_json_contract /tmp/dashboard_contract_policies.json policies

curl -fsS "http://127.0.0.1:8008/agents?tenant_id=${TENANT_ID}&limit=200" \
  -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" >/tmp/dashboard_contract_agents.json
assert_json_contract /tmp/dashboard_contract_agents.json agents

curl -fsS "http://127.0.0.1:8009/ai/providers" \
  -H "x-api-key: ${ROUTER_API_KEY}" >/tmp/dashboard_contract_providers.json
assert_json_contract /tmp/dashboard_contract_providers.json providers

curl -fsS "http://127.0.0.1:8011/events?tenant_id=${TENANT_ID}&limit=500" \
  -H "x-api-key: ${AUDIT_API_KEY}" >/tmp/dashboard_contract_events.json
assert_json_contract /tmp/dashboard_contract_events.json events

curl -fsS "http://127.0.0.1:8011/graph/agent/unknown?hours=1" \
  -H "x-api-key: ${AUDIT_API_KEY}" >/tmp/dashboard_contract_graph.json
assert_json_contract /tmp/dashboard_contract_graph.json graph

curl -fsS "http://127.0.0.1:8008/delegations?tenant_id=${TENANT_ID}&limit=200" \
  -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" >/tmp/dashboard_contract_delegations.json
assert_json_contract /tmp/dashboard_contract_delegations.json delegations

echo "[PASS] Dashboard API contract checks passed"
