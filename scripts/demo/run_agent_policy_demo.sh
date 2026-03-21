#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/infra/docker-compose/docker-compose.yml"
ENV_FILE="$ROOT_DIR/infra/docker-compose/.env"

BUILD=0
SEED_ONLY=0
NO_CACHE=0
TENANT_ID=""
MODE="block"

for arg in "$@"; do
  case "$arg" in
    --build) BUILD=1 ;;
    --seed-only) SEED_ONLY=1 ;;
    --no-cache) NO_CACHE=1 ;;
    --tenant=*) TENANT_ID="${arg#*=}" ;;
    --mode=*) MODE="${arg#*=}" ;;
    *)
      echo "Unknown option: $arg" >&2
      echo "Usage: $0 [--build] [--no-cache] [--seed-only] [--tenant=<id>] [--mode=block|redact]" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$TENANT_ID" ]]; then
  TENANT_ID="default"
fi

if [[ "$MODE" != "block" && "$MODE" != "redact" ]]; then
  echo "Invalid mode: $MODE (expected block or redact)" >&2
  exit 1
fi

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
  local retries="${3:-40}"
  local delay="${4:-2}"
  local i
  for ((i=1; i<=retries; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "  OK: $name"
      return 0
    fi
    sleep "$delay"
  done
  echo "  FAIL: $name did not become ready ($url)" >&2
  return 1
}

compose() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

AGENT_IDENTITY_API_KEY="${AGENT_IDENTITY_API_KEY:-$(load_env_var AGENT_IDENTITY_API_SECRET change-me-agent-identity)}"
POLICY_API_KEY="${POLICY_API_KEY:-$(load_env_var POLICY_API_SECRET change-me-policy)}"

echo "== Agent onboarding + policy assignment demo =="
echo "Tenant: $TENANT_ID"
echo "Mode:   $MODE"
echo

# Avoid known compose monitor crash path on some local Docker builds.
export COMPOSE_MENU=false

if [[ "$SEED_ONLY" -eq 0 ]]; then
  if [[ "$BUILD" -eq 1 && "$NO_CACHE" -eq 1 ]]; then
    echo "Building stack with --no-cache..."
    compose build --no-cache
    echo "Starting stack..."
    compose up -d
  elif [[ "$BUILD" -eq 1 ]]; then
    echo "Starting stack (with build)..."
    compose up -d --build
  else
    echo "Starting stack..."
    compose up -d
  fi
fi

echo "Waiting for services..."
wait_http "agent-identity" "http://127.0.0.1:8008/health"
wait_http "policy" "http://127.0.0.1:8001/health"
wait_http "dashboard" "http://127.0.0.1:3000/"

TS="$(date +%s)"
AGENT_NAME="demo-sales-assistant-${TS}"
OTHER_AGENT_NAME="demo-other-agent-${TS}"
POLICY_NAME="policy-${AGENT_NAME}-${MODE}-openai"

echo
echo "1) Register demo agent..."
AGENT_JSON="$(curl -fsS -X POST "http://127.0.0.1:8008/agents/register" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"name\":\"${AGENT_NAME}\",\"display_name\":\"${AGENT_NAME}\",\"owner_team\":\"security\",\"application\":\"demo-app\",\"trust_level\":\"restricted\",\"capabilities\":[\"ai:inference\"],\"allowed_tools\":[\"ai:inference\"],\"max_requests_per_minute\":60}")"
AGENT_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("agent_id",""))' <<<"$AGENT_JSON")"
if [[ -z "$AGENT_ID" ]]; then
  echo "Failed to register agent (missing agent_id): $AGENT_JSON" >&2
  exit 1
fi
echo "  Agent ID: $AGENT_ID"

echo
echo "2) Issue agent token..."
TOKEN_JSON="$(curl -fsS -X POST "http://127.0.0.1:8008/agents/${AGENT_ID}/tokens/issue" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"scopes\":[\"ai:inference\",\"ai:audit\"],\"expires_in\":3600}")"
TOKEN_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("token_id",""))' <<<"$TOKEN_JSON")"
echo "  Token ID: ${TOKEN_ID:-n/a}"

echo
echo "3) Create policy assigned to this agent..."
POLICY_ACTION="block"
POLICY_DESC="Block OpenAI chat completions for a specific agent"
if [[ "$MODE" == "redact" ]]; then
  POLICY_ACTION="allow"
  POLICY_DESC="Allow OpenAI calls with redaction controls for a specific agent"
fi
POLICY_JSON="$(curl -fsS -X POST "http://127.0.0.1:8001/policies" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${POLICY_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"name\":\"${POLICY_NAME}\",\"description\":\"${POLICY_DESC}\",\"action\":\"${POLICY_ACTION}\",\"priority\":10,\"enabled\":true,\"compliance_frameworks\":[\"NIST-CSF\",\"SOC2\"],\"tags\":[\"demo\",\"agent-assignment\",\"${MODE}\"],\"conditions\":{\"operator\":\"AND\",\"rules\":[{\"field\":\"metadata.agent_id\",\"operator\":\"equals\",\"value\":\"${AGENT_ID}\"},{\"field\":\"request.url\",\"operator\":\"contains\",\"value\":\"openai.com/v1/chat/completions\"}]}}")"
POLICY_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("id",""))' <<<"$POLICY_JSON")"
if [[ -z "$POLICY_ID" ]]; then
  echo "Failed to create policy (missing id): $POLICY_JSON" >&2
  exit 1
fi
echo "  Policy ID: $POLICY_ID"

echo
echo "4) Verify assignment behavior..."
MATCH_PAYLOAD="{\"context\":{\"request\":{\"url\":\"https://api.openai.com/v1/chat/completions\"},\"metadata\":{\"agent_id\":\"${AGENT_ID}\"}}}"
if [[ "$MODE" == "redact" ]]; then
  MATCH_PAYLOAD="{\"context\":{\"request\":{\"url\":\"https://api.openai.com/v1/chat/completions\"},\"metadata\":{\"agent_id\":\"${AGENT_ID}\"},\"redaction_targets\":[\"email\",\"ssn\",\"credit_card\"]}}"
fi
MATCHING_RES="$(curl -fsS -X POST "http://127.0.0.1:8001/policies/${TENANT_ID}/evaluate" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${POLICY_API_KEY}" \
  -d "${MATCH_PAYLOAD}")"

NONMATCH_RES="$(curl -fsS -X POST "http://127.0.0.1:8008/agents/register" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${AGENT_IDENTITY_API_KEY}" \
  -d "{\"tenant_id\":\"${TENANT_ID}\",\"name\":\"${OTHER_AGENT_NAME}\",\"display_name\":\"${OTHER_AGENT_NAME}\",\"owner_team\":\"security\",\"capabilities\":[\"ai:inference\"]}")"
OTHER_AGENT_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("agent_id",""))' <<<"$NONMATCH_RES")"
if [[ -z "$OTHER_AGENT_ID" ]]; then
  echo "Failed to register comparison agent" >&2
  exit 1
fi

NONMATCH_DECISION="$(curl -fsS -X POST "http://127.0.0.1:8001/policies/${TENANT_ID}/evaluate" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${POLICY_API_KEY}" \
  -d "{\"context\":{\"request\":{\"url\":\"https://api.openai.com/v1/chat/completions\"},\"metadata\":{\"agent_id\":\"${OTHER_AGENT_ID}\"}}}")"

echo "  Evaluation summary:"
python3 - "$MATCHING_RES" "$NONMATCH_DECISION" <<'PY'
import json
import sys

hit = json.loads(sys.argv[1])
miss = json.loads(sys.argv[2])

print(f"    assigned-agent decision: {hit.get('decision')} reason={hit.get('reason')} policy={hit.get('policy_name')}")
print(f"    other-agent    decision: {miss.get('decision')} reason={miss.get('reason')} policy={miss.get('policy_name')}")
PY

echo
echo "Demo complete."
echo "Dashboard walkthrough:"
echo "  - Agent Directory: http://localhost:3000/#/agents"
echo "  - Policy Builder:  http://localhost:3000/#/policy-builder"
echo "  - Policies:        http://localhost:3000/#/policies"
echo "  - Policy Studio:   http://localhost:3000/#/policy-studio"
echo
echo "Demo entities:"
echo "  - tenant_id : ${TENANT_ID}"
echo "  - agent_id  : ${AGENT_ID}"
echo "  - policy_id : ${POLICY_ID}"
echo
echo "Stop stack later with:"
echo "  docker compose -f ${COMPOSE_FILE} down"
