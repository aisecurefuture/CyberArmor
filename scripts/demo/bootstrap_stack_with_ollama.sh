#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/infra/docker-compose/docker-compose.yml"
MODEL_NAME="${MODEL_NAME:-llama3.2:3b}"
SKIP_BUILD=0

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=1 ;;
    *)
      echo "Unknown option: $arg" >&2
      echo "Usage: $0 [--skip-build]" >&2
      exit 1
      ;;
  esac
done

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
}

compose() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

wait_http() {
  local name="$1"
  local url="$2"
  local retries="${3:-60}"
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

install_host_ollama_if_needed() {
  if command -v ollama >/dev/null 2>&1; then
    echo "Host ollama already installed"
    return 0
  fi
  if ! command -v brew >/dev/null 2>&1; then
    echo "Host ollama not installed and Homebrew unavailable; continuing with container-only ollama"
    return 0
  fi
  echo "Installing host ollama with Homebrew..."
  brew install ollama
}

model_exists_in_container() {
  compose exec -T ollama ollama list 2>/dev/null | awk 'NR>1 {print $1}' | grep -Fxq "$MODEL_NAME"
}

require_cmd docker
require_cmd curl

export COMPOSE_MENU=false

echo "== CyberArmor bootstrap with Ollama model =="
echo "Compose file: $COMPOSE_FILE"
echo "Model: $MODEL_NAME"
echo

install_host_ollama_if_needed

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "Building stack with --no-cache..."
  compose build --no-cache
else
  echo "Skipping build step"
fi

echo "Starting stack..."
compose up -d

echo "Waiting for services..."
wait_http "ollama" "http://127.0.0.1:11434/api/tags"
wait_http "control-plane" "http://127.0.0.1:8000/health"
wait_http "detection" "http://127.0.0.1:8002/health"
wait_http "runtime" "http://127.0.0.1:8007/health"

if model_exists_in_container; then
  echo "Model already present: $MODEL_NAME"
else
  echo "Pulling model into ollama container: $MODEL_NAME"
  compose exec -T ollama ollama pull "$MODEL_NAME"
fi

echo
echo "Current Ollama models:"
compose exec -T ollama ollama list || true
echo
echo "Detection note:"
echo "  detection currently uses OLLAMA_ENABLED=false in docker-compose."
echo "  Pulling the model prepares the host/container cache; enable Ollama in detection before demos that need it."
echo
echo "Next commands if you want detection to use Ollama:"
echo "  1. Set OLLAMA_ENABLED=true for the detection service"
echo "  2. Recreate detection: docker compose -f $COMPOSE_FILE up -d --build detection"
