#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/infra/docker-compose/docker-compose.yml"
BUILD=0
SEED_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --build) BUILD=1 ;;
    --seed-only) SEED_ONLY=1 ;;
    *)
      echo "Unknown option: $arg" >&2
      echo "Usage: $0 [--build] [--seed-only]" >&2
      exit 1
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

compose() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

wait_http() {
  local name="$1"
  local url="$2"
  local max_tries="${3:-30}"
  local sleep_s="${4:-2}"
  local i=1

  printf "Waiting for %-18s %s\n" "$name" "$url"
  until curl -fsS "$url" >/dev/null 2>&1; do
    if [ "$i" -ge "$max_tries" ]; then
      echo "  FAIL: $name did not become ready in time" >&2
      return 1
    fi
    i=$((i+1))
    sleep "$sleep_s"
  done
  echo "  OK: $name"
}

echo "== CyberArmor live demo prep =="
echo "Repo root: $ROOT_DIR"
echo

# Avoid the Docker Compose monitor/menu path that has been crashing on some versions.
export COMPOSE_MENU=false

if [ "$SEED_ONLY" -eq 0 ]; then
  if [ "$BUILD" -eq 1 ]; then
    echo "Starting stack (with build)..."
    compose up -d --build
  else
    echo "Starting stack (no build)..."
    compose up -d
  fi

  echo
  wait_http "control-plane" "http://localhost:8000/health"
  wait_http "policy" "http://localhost:8001/health"
  wait_http "runtime" "http://localhost:8007/health"
  wait_http "proxy-agent" "http://localhost:8010/health"
  wait_http "dashboard" "http://localhost:3000/"
fi

echo
echo "Running proxy smoke tests..."
HTTP_PROXY_CODE="$(curl -s -o /dev/null -w "%{http_code}" -x http://127.0.0.1:8080 http://example.com || true)"
HTTPS_PROXY_CODE="$(curl --max-time 20 -s -o /dev/null -w "%{http_code}" -x http://127.0.0.1:8080 https://example.com || true)"
echo "  HTTP via proxy : $HTTP_PROXY_CODE"
echo "  HTTPS via proxy: $HTTPS_PROXY_CODE"

echo
echo "Seeding telemetry + incident data for dashboard visuals..."
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
REQUEST_ID="demo-$(date +%s)"

curl -fsS -X POST "http://localhost:8000/telemetry/ingest" \
  -H "Content-Type: application/json" \
  -H "x-api-key: change-me" \
  -d "{\"tenant_id\":\"default\",\"user_id\":\"demo-user\",\"source\":\"live_demo\",\"event_type\":\"demo_start\",\"metadata\":{\"ts\":\"$NOW_UTC\"}}" >/dev/null || true

curl -fsS -X POST "http://localhost:8000/agents/register" \
  -H "Content-Type: application/json" \
  -H "x-api-key: change-me" \
  -d '{"agent_id":"demo-agent-01","tenant_id":"default","hostname":"demo-mac","os":"macos","version":"1.0.0-demo"}' >/dev/null || true

curl -fsS -X POST "http://localhost:8000/agents/demo-agent-01/heartbeat" \
  -H "Content-Type: application/json" \
  -H "x-api-key: change-me" \
  -d '{"tenant_id":"default","status":"running","uptime_seconds":120,"active_monitors":["network","process"],"hostname":"demo-mac","os":"macos","version":"1.0.0-demo"}' >/dev/null || true

curl -fsS -X POST "http://localhost:8000/incidents/ingest" \
  -H "Content-Type: application/json" \
  -H "x-api-key: change-me" \
  -d "{\"tenant_id\":\"default\",\"request_id\":\"$REQUEST_ID\",\"event_type\":\"runtime_decision\",\"decision\":\"block\",\"reasons\":[\"synthetic_demo_block\"],\"metadata\":{\"source\":\"live_demo\",\"ts\":\"$NOW_UTC\"}}" >/dev/null || true

echo "  Seeded request_id: $REQUEST_ID"

echo
echo "Running direct runtime decision demo..."
RUNTIME_BODY_FILE="$(mktemp)"
RUNTIME_HTTP_CODE=""
for attempt in 1 2 3; do
  RUNTIME_HTTP_CODE="$(curl --max-time 20 -sS -o "$RUNTIME_BODY_FILE" -w "%{http_code}" "http://localhost:8007/runtime/evaluate" \
    -H "Content-Type: application/json" \
    -d '{"tenant_id":"default","content":"AKIA1234567890ABCDEF","metadata":{"url":"https://chatgpt.com","method":"POST","host":"chatgpt.com","client_ip":"127.0.0.1","direction":"request"}}' || true)"
  if [ "$RUNTIME_HTTP_CODE" = "200" ]; then
    break
  fi
  sleep 2
done
RUNTIME_JSON="$(cat "$RUNTIME_BODY_FILE" 2>/dev/null || true)"

if [ "$RUNTIME_HTTP_CODE" = "200" ] && [ -n "$RUNTIME_JSON" ]; then
  RUNTIME_SUMMARY="$(python3 - "$RUNTIME_BODY_FILE" <<'PY'
import json, sys
p = sys.argv[1]
with open(p, "r", encoding="utf-8") as f:
    d = json.load(f)
rid = d.get("request_id", "n/a")
decision = d.get("decision", "unknown")
reasons = d.get("reasons", [])
risk = d.get("risk", {})
print(f'request_id={rid} decision={decision} reasons={len(reasons)} findings={risk.get("findings","n/a")}')
PY
  )"
  echo "  runtime/evaluate => $RUNTIME_SUMMARY"
else
  echo "  runtime/evaluate => (HTTP ${RUNTIME_HTTP_CODE:-000}) $RUNTIME_JSON"
fi
rm -f "$RUNTIME_BODY_FILE"

echo
echo "Demo surfaces:"
echo "  Dashboard:      http://localhost:3000"
echo "  Telemetry view: http://localhost:3000/#/telemetry"
echo "  Incidents view: http://localhost:3000/#/incidents"
echo "  Demo web app:   http://localhost:8020"
echo
echo "Quick presenter checks:"
echo "  - Telemetry page shows Active Agents >= 1"
echo "  - Incidents page includes request_id: $REQUEST_ID"
echo "  - Proxy HTTP/HTTPS status codes shown above are not 000/502"
echo
echo "Stop stack later with:"
echo "  docker compose -f $COMPOSE_FILE down"
