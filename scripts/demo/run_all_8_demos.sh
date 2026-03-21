#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
QUICK=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    *) echo "Unknown option: $arg" >&2; echo "Usage: $0 [--quick]" >&2; exit 1 ;;
  esac
done

echo "== CyberArmor Demo Pack: all 8 demos =="

bash "$ROOT_DIR/scripts/demo/run_demo_1_attack_to_action.sh"
bash "$ROOT_DIR/scripts/demo/run_demo_2_human_approval.sh"
bash "$ROOT_DIR/scripts/demo/run_demo_3_delegation_chain.sh"
bash "$ROOT_DIR/scripts/demo/run_demo_4_tenant_isolation.sh"
bash "$ROOT_DIR/scripts/demo/run_demo_5_provider_governance.sh"
bash "$ROOT_DIR/scripts/demo/run_demo_6_incident_triage.sh"
bash "$ROOT_DIR/scripts/demo/run_demo_7_key_rotation.sh"
bash "$ROOT_DIR/scripts/demo/run_demo_8_compliance_evidence.sh"

echo
echo "All 8 demos completed."
echo "Dashboard: http://localhost:3000"
