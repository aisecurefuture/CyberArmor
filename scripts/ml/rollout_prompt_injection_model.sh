#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${ROOT_DIR}/infra/docker-compose/.env"
MODEL_DIR="${1:-${ROOT_DIR}/models/prompt-injection-distilbert}"

if [[ ! -f "${MODEL_DIR}/config.json" ]]; then
  echo "Model directory missing config.json: ${MODEL_DIR}" >&2
  exit 2
fi
if [[ ! -f "${MODEL_DIR}/tokenizer.json" && ! -f "${MODEL_DIR}/tokenizer_config.json" ]]; then
  echo "Model directory missing tokenizer artifacts: ${MODEL_DIR}" >&2
  exit 2
fi

mkdir -p "$(dirname "${ENV_FILE}")"
touch "${ENV_FILE}"

upsert_env() {
  local key="$1"
  local val="$2"
  if grep -qE "^${key}=" "${ENV_FILE}"; then
    sed -i '' -E "s|^${key}=.*|${key}=${val}|" "${ENV_FILE}"
  else
    printf "%s=%s\n" "${key}" "${val}" >> "${ENV_FILE}"
  fi
}

upsert_env "PROMPT_INJECTION_MODEL_BACKEND" "transformer"
upsert_env "PROMPT_INJECTION_MODEL_PATH" "${MODEL_DIR}"
upsert_env "PROMPT_INJECTION_MODEL_POSITIVE_LABEL_INDEX" "1"

echo "Updated ${ENV_FILE} for transformer rollout:"
echo " - PROMPT_INJECTION_MODEL_BACKEND=transformer"
echo " - PROMPT_INJECTION_MODEL_PATH=${MODEL_DIR}"
echo " - PROMPT_INJECTION_MODEL_POSITIVE_LABEL_INDEX=1"
echo
echo "Next command:"
echo "  docker compose -f ${ROOT_DIR}/infra/docker-compose/docker-compose.yml up -d --build detection"

