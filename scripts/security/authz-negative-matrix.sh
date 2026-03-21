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

check_denied() {
  local name="$1"
  local method="$2"
  local url="$3"
  local body="${4:-}"
  local code

  if [[ "$method" == "GET" ]]; then
    code=$(curl -s -o /tmp/authz_neg_${name}.json -w '%{http_code}' "$url")
  else
    code=$(curl -s -o /tmp/authz_neg_${name}.json -w '%{http_code}' \
      -X "$method" \
      -H "Content-Type: application/json" \
      -d "$body" \
      "$url")
  fi

  if [[ "$code" != "401" && "$code" != "403" ]]; then
    echo "[FAIL] ${name}: expected 401/403, got ${code}" >&2
    cat /tmp/authz_neg_${name}.json >&2 || true
    exit 1
  fi
  echo "[OK] ${name}: denied (${code})"
}

check_denied_with_headers() {
  local name="$1"
  local method="$2"
  local url="$3"
  local headers="$4"
  local body="${5:-}"
  local code

  if [[ "$method" == "GET" ]]; then
    # shellcheck disable=SC2086
    code=$(curl -s -o /tmp/authz_neg_${name}.json -w '%{http_code}' $headers "$url")
  else
    # shellcheck disable=SC2086
    code=$(curl -s -o /tmp/authz_neg_${name}.json -w '%{http_code}' \
      -X "$method" \
      -H "Content-Type: application/json" \
      $headers \
      -d "$body" \
      "$url")
  fi

  if [[ "$code" != "401" && "$code" != "403" ]]; then
    echo "[FAIL] ${name}: expected 401/403, got ${code}" >&2
    cat /tmp/authz_neg_${name}.json >&2 || true
    exit 1
  fi
  echo "[OK] ${name}: denied (${code})"
}

check_allowed_with_headers() {
  local name="$1"
  local method="$2"
  local url="$3"
  local headers="$4"
  local body="${5:-}"
  local code

  if [[ "$method" == "GET" ]]; then
    # shellcheck disable=SC2086
    code=$(curl -s -o /tmp/authz_pos_${name}.json -w '%{http_code}' $headers "$url")
  else
    # shellcheck disable=SC2086
    code=$(curl -s -o /tmp/authz_pos_${name}.json -w '%{http_code}' \
      -X "$method" \
      -H "Content-Type: application/json" \
      $headers \
      -d "$body" \
      "$url")
  fi

  if [[ "$code" == "401" || "$code" == "403" ]]; then
    echo "[FAIL] ${name}: expected authorized (non-401/403), got ${code}" >&2
    cat /tmp/authz_pos_${name}.json >&2 || true
    exit 1
  fi
  echo "[OK] ${name}: authorized path reachable (${code})"
}

echo "[STEP] authz negative matrix"
check_denied "agent_identity_agents" "GET" "http://127.0.0.1:8008/agents?tenant_id=default"
check_denied "agent_identity_get_agent" "GET" "http://127.0.0.1:8008/agents/agt_fake"
check_denied "agent_identity_issue_token" "POST" "http://127.0.0.1:8008/agents/agt_fake/tokens/issue" '{"tenant_id":"default","scopes":["ai:inference"],"expires_in":3600}'
check_denied "agent_identity_validate_token" "POST" "http://127.0.0.1:8008/agents/agt_fake/tokens/validate" '{"token":"fake"}'
check_denied "agent_identity_revoke_token" "POST" "http://127.0.0.1:8008/agents/agt_fake/tokens/revoke" '{"token_id":"tok_fake"}'
check_denied "agent_identity_workload_get" "GET" "http://127.0.0.1:8008/workloads/wrk_fake"
check_denied "agent_identity_delegations_list" "GET" "http://127.0.0.1:8008/delegations"
check_denied "agent_identity_delegation_get" "GET" "http://127.0.0.1:8008/delegations/del_fake"
check_denied "agent_identity_delegation_delete" "DELETE" "http://127.0.0.1:8008/delegations/del_fake"

check_denied "policy_list" "GET" "http://127.0.0.1:8001/policies/default"
check_denied "policy_evaluate" "POST" "http://127.0.0.1:8001/policies/evaluate" '{"tenant_id":"default","context":{"provider":"openai","model":"gpt-4o-mini"}}'
check_denied "policy_evaluate_batch" "POST" "http://127.0.0.1:8001/policies/evaluate/batch" '{"tenant_id":"default","requests":[{"provider":"openai"}]}'
check_denied "policy_import" "POST" "http://127.0.0.1:8001/policies/import" '{"tenant_id":"default","policy_name":"p1","source":"permit(principal, action, resource);","format":"cedar"}'
check_denied "policy_simulate" "GET" "http://127.0.0.1:8001/policies/simulate?tenant_id=default&context_json=%7B%7D"
check_denied "policy_explain" "GET" "http://127.0.0.1:8001/policies/explain/req_fake"

check_denied "ai_router_providers" "GET" "http://127.0.0.1:8009/ai/providers"
check_denied "ai_router_models" "GET" "http://127.0.0.1:8009/ai/models"
check_denied "ai_router_chat" "POST" "http://127.0.0.1:8009/ai/chat/completions" '{"tenant_id":"default","provider":"openai","model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
check_denied "ai_router_credentials_status" "GET" "http://127.0.0.1:8009/credentials/providers/openai/status?tenant_id=default"
check_denied "ai_router_credentials_configure" "POST" "http://127.0.0.1:8009/credentials/providers/openai/configure?tenant_id=default" '{"api_key":"sk-test","default_model":"gpt-4o-mini"}'

check_denied "audit_events" "GET" "http://127.0.0.1:8011/events?tenant_id=default"
check_denied "audit_graph_agent" "GET" "http://127.0.0.1:8011/graph/agent/agt_fake"
check_denied "audit_graph_human" "GET" "http://127.0.0.1:8011/graph/human/usr_fake"
check_denied "audit_timeline" "GET" "http://127.0.0.1:8011/timeline?tenant_id=default"
check_denied "audit_export" "POST" "http://127.0.0.1:8011/export" '{"tenant_id":"default"}'
check_denied "audit_integrity_verify" "GET" "http://127.0.0.1:8011/integrity/verify/evt_fake"
check_denied "audit_signing_key_status" "GET" "http://127.0.0.1:8011/integrity/signing-key/status"

check_denied "identity_providers" "GET" "http://127.0.0.1:8004/providers"
check_denied "detection_scan" "POST" "http://127.0.0.1:8002/scan" '{"content":"hello","tenant_id":"default"}'
check_denied "siem_ingest" "POST" "http://127.0.0.1:8005/ingest" '{"event_type":"test","tenant_id":"default","source_service":"test"}'

echo "[STEP] role-based and cross-tenant negative checks"
CONTROL_PLANE_KEY="$(load_env_var CYBERARMOR_API_SECRET change-me)"
ROLE_HEADERS="-H x-api-key:${CONTROL_PLANE_KEY} -H x-role:analyst"
check_denied_with_headers "control_plane_admin_endpoint_role" "GET" "http://127.0.0.1:8000/apikeys" "$ROLE_HEADERS"
check_denied_with_headers "control_plane_admin_create_tenant_role" "POST" "http://127.0.0.1:8000/tenants" "$ROLE_HEADERS" '{"id":"tenant-neg-role","name":"Tenant Neg Role"}'
check_denied_with_headers "control_plane_admin_audit_logs_role" "GET" "http://127.0.0.1:8000/audit/logs" "$ROLE_HEADERS"
check_denied_with_headers "control_plane_admin_create_apikey_role" "POST" "http://127.0.0.1:8000/apikeys" "$ROLE_HEADERS" '{"tenant_id":"default","role":"analyst"}'

TENANT_MISMATCH_HEADERS="-H x-api-key:${CONTROL_PLANE_KEY} -H x-role:analyst -H x-tenant-id:tenant-a"
check_denied_with_headers \
  "control_plane_tenant_mismatch" \
  "POST" \
  "http://127.0.0.1:8000/telemetry/ingest" \
  "$TENANT_MISMATCH_HEADERS" \
  '{"tenant_id":"tenant-b","event_type":"security_test","source":"authz-negative-matrix","payload":{"case":"tenant-mismatch"}}'

echo "[STEP] positive authorization checks"
ADMIN_HEADERS="-H x-api-key:${CONTROL_PLANE_KEY} -H x-role:admin"
check_allowed_with_headers "control_plane_admin_list_tenants" "GET" "http://127.0.0.1:8000/tenants" "$ADMIN_HEADERS"
check_allowed_with_headers "control_plane_admin_list_apikeys" "GET" "http://127.0.0.1:8000/apikeys" "$ADMIN_HEADERS"
check_allowed_with_headers "control_plane_admin_audit_logs" "GET" "http://127.0.0.1:8000/audit/logs" "$ADMIN_HEADERS"

TENANT_MATCH_HEADERS="-H x-api-key:${CONTROL_PLANE_KEY} -H x-role:analyst -H x-tenant-id:tenant-a"
check_allowed_with_headers \
  "control_plane_tenant_match_ingest" \
  "POST" \
  "http://127.0.0.1:8000/telemetry/ingest" \
  "$TENANT_MATCH_HEADERS" \
  '{"tenant_id":"tenant-a","event_type":"security_test","source":"authz-negative-matrix","payload":{"case":"tenant-match"}}'

echo "[PASS] Authz negative matrix passed"
