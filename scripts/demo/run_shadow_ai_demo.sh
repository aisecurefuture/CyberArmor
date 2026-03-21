#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT_DIR/scripts/demo/lib_demo.sh"

TENANT_ID="${TENANT_ID:-default}"
CP_KEY="${CP_KEY:-$(load_env_var CYBERARMOR_API_SECRET change-me)}"
TS="$(date +%s)"
AGENT_ID="shadow-demo-${TS}"

echo "== Shadow AI Demo Seed =="
echo "Tenant: $TENANT_ID"

wait_http "control-plane" "http://127.0.0.1:8000/health"

curl -fsS -X POST "http://127.0.0.1:8000/agents/register" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${CP_KEY}" \
  -d "{\"agent_id\":\"${AGENT_ID}\",\"tenant_id\":\"${TENANT_ID}\",\"hostname\":\"demo-macbook\",\"os\":\"macos\",\"version\":\"1.0.0-demo\"}" >/dev/null

curl -fsS -X POST "http://127.0.0.1:8000/agents/${AGENT_ID}/telemetry" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${CP_KEY}" \
  -d "{
    \"tenant_id\":\"${TENANT_ID}\",
    \"events\":[
      {
        \"source\":\"process_monitor\",
        \"event_type\":\"ai_tool_process_detected\",
        \"timestamp\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\",
        \"tool_name\":\"OpenAI Desktop\",
        \"process_name\":\"OpenAI\",
        \"exe\":\"/Applications/OpenAI.app\",
        \"username\":\"patrick\",
        \"hostname\":\"demo-macbook\",
        \"severity\":\"high\"
      },
      {
        \"source\":\"network_monitor\",
        \"event_type\":\"ai_service_connection_detected\",
        \"timestamp\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\",
        \"service\":\"ChatGPT\",
        \"domain\":\"chatgpt.com\",
        \"remote_ip\":\"104.18.33.45\",
        \"process_name\":\"Safari\",
        \"username\":\"patrick\",
        \"hostname\":\"demo-macbook\",
        \"severity\":\"high\"
      },
      {
        \"source\":\"process_monitor\",
        \"event_type\":\"ai_tool_process_detected\",
        \"timestamp\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\",
        \"tool_name\":\"Claude Desktop\",
        \"process_name\":\"Claude\",
        \"exe\":\"/Applications/Claude.app\",
        \"username\":\"patrick\",
        \"hostname\":\"demo-macbook\",
        \"severity\":\"medium\"
      }
    ]
  }" >/dev/null

echo "Seeded agent_id: $AGENT_ID"
echo "Open: http://localhost:3000/#/shadow-ai"
