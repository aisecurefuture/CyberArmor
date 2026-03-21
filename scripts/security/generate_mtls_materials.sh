#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-infra/docker-compose/certs}"
DAYS="${DAYS:-30}"

mkdir -p "${OUT_DIR}"

CA_KEY="${OUT_DIR}/ca.key"
CA_CRT="${OUT_DIR}/ca.crt"
SVC_KEY="${OUT_DIR}/tls.key"
SVC_CSR="${OUT_DIR}/tls.csr"
SVC_CRT="${OUT_DIR}/tls.crt"

openssl genrsa -out "${CA_KEY}" 4096
openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days "${DAYS}" \
  -subj "/CN=cyberarmor-local-ca" -out "${CA_CRT}"

openssl genrsa -out "${SVC_KEY}" 2048
openssl req -new -key "${SVC_KEY}" -subj "/CN=cyberarmor-local-client" -out "${SVC_CSR}"
openssl x509 -req -in "${SVC_CSR}" -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
  -out "${SVC_CRT}" -days "${DAYS}" -sha256

rm -f "${SVC_CSR}" "${OUT_DIR}/ca.srl"

echo "MTLS_MATERIALS_GENERATED ${OUT_DIR}"
