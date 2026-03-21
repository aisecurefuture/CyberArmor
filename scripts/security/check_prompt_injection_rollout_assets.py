#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ENV_EXAMPLE = ROOT / "infra/docker-compose/.env.example"
DETECTION_MAIN = ROOT / "services/detection/main.py"
ROLL_RUNBOOK = ROOT / "docs/runbooks/prompt-injection-transformer-rollout.md"
TRAIN_SCRIPT = ROOT / "scripts/ml/train_prompt_injection_transformer.py"
PREP_SCRIPT = ROOT / "scripts/ml/prepare_prompt_injection_dataset.py"
SEED_GEN_SCRIPT = ROOT / "scripts/ml/generate_seed_prompt_injection_dataset.py"
SEED_DATASET = ROOT / "data/prompt_injection/seed_prompt_injection_v1.jsonl"
ROLLOUT_SCRIPT = ROOT / "scripts/ml/rollout_prompt_injection_model.sh"


def _require_file(path: Path, issues: list[str]) -> None:
    if not path.exists():
        issues.append(f"missing file: {path.relative_to(ROOT)}")


def _require_markers(path: Path, markers: list[str], issues: list[str], label: str) -> None:
    text = path.read_text(encoding="utf-8", errors="ignore")
    for m in markers:
        if m not in text:
            issues.append(f"{label} missing marker: {m}")


def _validate_model_dirs(issues: list[str]) -> None:
    models_root = ROOT / "models"
    if not models_root.exists():
        return
    model_dirs = [p for p in models_root.glob("prompt-injection*") if p.is_dir()]
    for d in model_dirs:
        required_files = ["config.json", "training_manifest.json"]
        if not ((d / "tokenizer.json").exists() or (d / "tokenizer_config.json").exists()):
            issues.append(f"model dir missing tokenizer artifact: {d.relative_to(ROOT)}")
        for rf in required_files:
            if not (d / rf).exists():
                issues.append(f"model dir missing required file: {(d / rf).relative_to(ROOT)}")
        manifest = d / "training_manifest.json"
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
            except Exception as exc:
                issues.append(f"invalid JSON manifest {manifest.relative_to(ROOT)}: {exc}")
                continue
            for k in ["task", "base_model", "positive_label_index", "metrics"]:
                if k not in data:
                    issues.append(f"manifest missing key '{k}' in {manifest.relative_to(ROOT)}")
            if isinstance(data.get("metrics"), dict):
                for mk in ["eval_f1", "eval_precision", "eval_recall"]:
                    if mk not in data["metrics"]:
                        issues.append(f"manifest metrics missing '{mk}' in {manifest.relative_to(ROOT)}")
            else:
                issues.append(f"manifest 'metrics' is not object in {manifest.relative_to(ROOT)}")


def main() -> int:
    issues: list[str] = []

    for p in [
        ENV_EXAMPLE,
        DETECTION_MAIN,
        ROLL_RUNBOOK,
        TRAIN_SCRIPT,
        PREP_SCRIPT,
        SEED_GEN_SCRIPT,
        SEED_DATASET,
        ROLLOUT_SCRIPT,
    ]:
        _require_file(p, issues)
    if issues:
        _fail(issues)
        return 1

    _require_markers(
        ENV_EXAMPLE,
        [
            "PROMPT_INJECTION_MODEL_BACKEND",
            "PROMPT_INJECTION_MODEL_PATH",
            "PROMPT_INJECTION_MODEL_POSITIVE_LABEL_INDEX",
        ],
        issues,
        "env example",
    )
    _require_markers(
        DETECTION_MAIN,
        [
            "PROMPT_INJECTION_MODEL_BACKEND",
            "PROMPT_INJECTION_MODEL_PATH",
            "AutoModelForSequenceClassification",
            "TransformerPromptInjectionModel",
        ],
        issues,
        "detection main",
    )
    _require_markers(
        ROLL_RUNBOOK,
        [
            "prepare_prompt_injection_dataset.py",
            "seed_prompt_injection_v1.jsonl",
            "generate_seed_prompt_injection_dataset.py",
            "train_prompt_injection_transformer.py",
            "rollout_prompt_injection_model.sh",
            "PROMPT_INJECTION_MODEL_BACKEND=transformer",
        ],
        issues,
        "rollout runbook",
    )

    _validate_model_dirs(issues)

    if issues:
        _fail(issues)
        return 1
    print("PROMPT_INJECTION_ROLLOUT_ASSETS_CHECK_OK")
    return 0


def _fail(issues: list[str]) -> None:
    print("PROMPT_INJECTION_ROLLOUT_ASSETS_CHECK_FAILED")
    for i in issues:
        print(f" - {i}")


if __name__ == "__main__":
    raise SystemExit(main())
