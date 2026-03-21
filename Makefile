.PHONY: dist dist-commercial clean-dist verify-brand-surface verify-cyberarmor-brand verify-dashboard-contract demo

# Build CyberArmor distribution zip from this single repo.
#
# dist                  -> CyberArmor commercial zip
# verify-brand-surface  -> fail if brand tokens appear outside controlled surface
# verify-cyberarmor-brand -> fail if dual-brand staging/targets reappear
# demo                  -> bring up docker-compose and run a small smoke test

DIST_DIR := dist

COMM_ZIP := $(DIST_DIR)/CyberArmor-commercial.zip

PY := python3

clean-dist:
	rm -rf $(DIST_DIR)

$(COMM_ZIP):
	$(PY) scripts/branding/build.py --brand cyberarmor --out $(COMM_ZIP)

dist: dist-commercial

dist-commercial: $(COMM_ZIP)
	@echo "Built: $(COMM_ZIP)"

verify-brand-surface:
	$(PY) scripts/branding/verify_surface.py

verify-cyberarmor-brand:
	$(PY) scripts/security/check_cyberarmor_single_brand.py

verify-dashboard-contract:
	bash scripts/dashboard-api-contract.sh

# One-command demo (requires docker + docker compose)
demo:
	bash scripts/demo/run_demo.sh
