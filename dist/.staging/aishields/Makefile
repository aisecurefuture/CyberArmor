.PHONY: dist-oss dist-commercial clean-dist verify-brand-surface demo

# Build branded distribution zips from this single repo.
#
# dist-oss         -> AIShields OSS zip
# dist-commercial  -> CyberArmor.ai commercial zip
# verify-brand-surface -> fail if brand tokens appear outside controlled surface
# demo             -> bring up docker-compose and run a small smoke test

DIST_DIR := dist

OSS_ZIP := $(DIST_DIR)/AIShields-oss.zip
COMM_ZIP := $(DIST_DIR)/CyberArmor-commercial.zip

PY := python3

clean-dist:
	rm -rf $(DIST_DIR)

$(OSS_ZIP):
	$(PY) scripts/dualbrand/build.py --brand aishields --out $(OSS_ZIP)

$(COMM_ZIP):
	$(PY) scripts/dualbrand/build.py --brand cyberarmor --out $(COMM_ZIP)

dist-oss: $(OSS_ZIP)
	@echo "Built: $(OSS_ZIP)"

dist-commercial: $(COMM_ZIP)
	@echo "Built: $(COMM_ZIP)"

verify-brand-surface:
	$(PY) scripts/dualbrand/verify_surface.py

# One-command demo (requires docker + docker compose)
demo:
	bash scripts/demo/run_demo.sh
