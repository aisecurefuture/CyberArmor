#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALLER="${REPO_ROOT}/agents/endpoint-agent/installer.py"
CONFIG_PATH="/etc/cyberarmor/agent.json"
PLIST_PATH="/Library/LaunchDaemons/ai.cyberarmor.endpoint.plist"
LOG_DIR="/var/log/cyberarmor"
PYTHON_BIN=""

CONTROL_PLANE_URL=""
TENANT_ID=""
API_KEY=""
INSTALL_DIR=""

usage() {
  cat <<'EOF'
Usage:
  zsh scripts/endpoint/reinstall_endpoint_agent.zsh [options]

Options:
  --control-plane-url URL   Override control plane URL
  --tenant-id TENANT        Override tenant ID
  --api-key KEY             Override API key
  --install-dir PATH        Override install directory
  -h, --help                Show this help

Behavior:
  - Reads /etc/cyberarmor/agent.json if present and reuses its values
  - Unloads the existing macOS launchd service if present
  - Re-runs the endpoint installer in silent mode
  - Prints the resulting config and recent logs
EOF
}

resolve_python() {
  if [[ -n "${PYTHON_BIN}" ]]; then
    return 0
  fi
  for candidate in /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if [[ -x "${candidate}" ]]; then
      PYTHON_BIN="${candidate}"
      return 0
    fi
  done
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
    return 0
  fi
  echo "python3 not found. Install Python 3 and rerun." >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --control-plane-url)
      CONTROL_PLANE_URL="${2:-}"
      shift 2
      ;;
    --tenant-id)
      TENANT_ID="${2:-}"
      shift 2
      ;;
    --api-key)
      API_KEY="${2:-}"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ ! -f "${INSTALLER}" ]]; then
  echo "Installer not found: ${INSTALLER}" >&2
  exit 1
fi

resolve_python

read_json_value() {
  local key="$1"
  local path="$2"
  "${PYTHON_BIN}" - "$key" "$path" <<'PY'
import json
import sys
from pathlib import Path

key = sys.argv[1]
path = Path(sys.argv[2])
if not path.exists():
    print("")
    raise SystemExit(0)
try:
    data = json.loads(path.read_text())
except Exception:
    print("")
    raise SystemExit(0)
value = data.get(key, "")
print("" if value is None else str(value))
PY
}

if [[ -z "${CONTROL_PLANE_URL}" ]]; then
  CONTROL_PLANE_URL="$(read_json_value control_plane_url "${CONFIG_PATH}")"
fi
if [[ -z "${TENANT_ID}" ]]; then
  TENANT_ID="$(read_json_value tenant_id "${CONFIG_PATH}")"
fi
if [[ -z "${API_KEY}" ]]; then
  API_KEY="$(read_json_value api_key "${CONFIG_PATH}")"
fi

CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-http://localhost:8000}"
TENANT_ID="${TENANT_ID:-default}"
API_KEY="${API_KEY:-change-me}"

echo "Reinstalling endpoint agent with:"
echo "  control_plane_url=${CONTROL_PLANE_URL}"
echo "  tenant_id=${TENANT_ID}"
echo "  installer=${INSTALLER}"

if [[ -f "${PLIST_PATH}" ]]; then
  echo "Unloading existing launchd service"
  sudo launchctl unload "${PLIST_PATH}" >/dev/null 2>&1 || true
fi

INSTALL_CMD=(
  "${PYTHON_BIN}"
  "${INSTALLER}"
  install
  --silent
  --control-plane-url "${CONTROL_PLANE_URL}"
  --tenant-id "${TENANT_ID}"
  --api-key "${API_KEY}"
)

if [[ -n "${INSTALL_DIR}" ]]; then
  INSTALL_CMD+=(--install-dir "${INSTALL_DIR}")
fi

echo "Running installer"
sudo "${INSTALL_CMD[@]}"

echo
echo "Installed config:"
sudo cat "${CONFIG_PATH}" || true

echo
echo "Recent endpoint agent logs:"
sudo mkdir -p "${LOG_DIR}" >/dev/null 2>&1 || true
sudo tail -n 40 "${LOG_DIR}/agent.err" 2>/dev/null || echo "(no agent.err yet)"
