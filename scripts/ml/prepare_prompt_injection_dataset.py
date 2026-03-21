#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


@dataclass
class Row:
    text: str
    label: int
    source: str


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Normalize mixed prompt-injection datasets into train/eval JSONL format."
    )
    p.add_argument(
        "--inputs",
        nargs="+",
        default=[],
        help="Input files (.jsonl, .json, .csv).",
    )
    p.add_argument(
        "--default-seed-input",
        default="data/prompt_injection/seed_prompt_injection_v1.jsonl",
        help="Bundled seed dataset used when --inputs is omitted.",
    )
    p.add_argument("--output-train", required=True, help="Output JSONL path for train set.")
    p.add_argument("--output-eval", default="", help="Optional output JSONL path for eval set.")
    p.add_argument("--eval-ratio", type=float, default=0.1, help="Eval split ratio if --output-eval provided.")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--text-field", default="text")
    p.add_argument("--label-field", default="label")
    p.add_argument(
        "--positive-labels",
        default="1,true,yes,malicious,prompt_injection,jailbreak,attack",
        help="Comma-separated values considered positive.",
    )
    p.add_argument(
        "--negative-labels",
        default="0,false,no,benign,safe,normal",
        help="Comma-separated values considered negative.",
    )
    p.add_argument("--min-text-len", type=int, default=8)
    p.add_argument("--max-text-len", type=int, default=6000)
    return p.parse_args()


def _norm_space(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()


def _norm_label(raw, pos: set[str], neg: set[str]) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, bool):
        return 1 if raw else 0
    if isinstance(raw, int):
        return 1 if raw == 1 else 0 if raw == 0 else None
    val = str(raw).strip().lower()
    if val in pos:
        return 1
    if val in neg:
        return 0
    if val == "1":
        return 1
    if val == "0":
        return 0
    return None


def _iter_jsonl(path: Path) -> Iterable[Dict]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                yield obj


def _iter_json(path: Path) -> Iterable[Dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item
    elif isinstance(data, dict):
        items = data.get("data") or data.get("items") or data.get("records")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    yield item


def _iter_csv(path: Path) -> Iterable[Dict]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield dict(row)


def _read_records(path: Path) -> Iterable[Dict]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        return _iter_jsonl(path)
    if suffix == ".json":
        return _iter_json(path)
    if suffix == ".csv":
        return _iter_csv(path)
    return []


def _stratified_split(rows: List[Row], ratio: float, seed: int) -> Tuple[List[Row], List[Row]]:
    pos = [r for r in rows if r.label == 1]
    neg = [r for r in rows if r.label == 0]
    rng = random.Random(seed)
    rng.shuffle(pos)
    rng.shuffle(neg)
    pos_cut = max(1, int(len(pos) * ratio)) if pos else 0
    neg_cut = max(1, int(len(neg) * ratio)) if neg else 0
    eval_rows = pos[:pos_cut] + neg[:neg_cut]
    train_rows = pos[pos_cut:] + neg[neg_cut:]
    rng.shuffle(eval_rows)
    rng.shuffle(train_rows)
    if not train_rows or not eval_rows:
        raise ValueError("Split produced empty train/eval set. Add more data or lower eval ratio.")
    return train_rows, eval_rows


def _write_jsonl(path: Path, rows: List[Row]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(
                json.dumps(
                    {"text": r.text, "label": r.label, "source": r.source},
                    ensure_ascii=True,
                )
                + "\n"
            )


def main() -> int:
    args = parse_args()
    pos_labels = {v.strip().lower() for v in args.positive_labels.split(",") if v.strip()}
    neg_labels = {v.strip().lower() for v in args.negative_labels.split(",") if v.strip()}
    if not 0.0 < args.eval_ratio < 0.5:
        raise ValueError("--eval-ratio must be in (0, 0.5)")

    input_paths: List[Path]
    if args.inputs:
        input_paths = [Path(x).resolve() for x in args.inputs]
    else:
        repo_root = Path(__file__).resolve().parents[2]
        input_paths = [(repo_root / args.default_seed_input).resolve()]

    all_rows: List[Row] = []
    for p in input_paths:
        if not p.exists():
            raise FileNotFoundError(f"Input file not found: {p}")
        source = p.name
        for rec in _read_records(p):
            text = _norm_space(str(rec.get(args.text_field, "")))
            if len(text) < args.min_text_len or len(text) > args.max_text_len:
                continue
            lbl = _norm_label(rec.get(args.label_field), pos_labels, neg_labels)
            if lbl is None:
                continue
            all_rows.append(Row(text=text, label=lbl, source=source))

    if not all_rows:
        raise ValueError("No valid rows found after normalization.")

    # Deduplicate by normalized text + label.
    dedup: Dict[Tuple[str, int], Row] = {}
    for r in all_rows:
        key = (_norm_space(r.text).lower(), r.label)
        if key not in dedup:
            dedup[key] = r
    rows = list(dedup.values())

    # Shuffle globally.
    rng = random.Random(args.seed)
    rng.shuffle(rows)

    output_train = Path(args.output_train).resolve()
    output_eval = Path(args.output_eval).resolve() if args.output_eval else None

    if output_eval:
        train_rows, eval_rows = _stratified_split(rows, ratio=args.eval_ratio, seed=args.seed)
        _write_jsonl(output_train, train_rows)
        _write_jsonl(output_eval, eval_rows)
        summary = {
            "train_rows": len(train_rows),
            "eval_rows": len(eval_rows),
        }
    else:
        _write_jsonl(output_train, rows)
        summary = {"train_rows": len(rows), "eval_rows": 0}

    pos_count = sum(1 for r in rows if r.label == 1)
    neg_count = sum(1 for r in rows if r.label == 0)
    print("PROMPT_INJECTION_DATASET_PREP_OK")
    print(
        json.dumps(
            {
                "total_rows": len(rows),
                "positive_rows": pos_count,
                "negative_rows": neg_count,
                "outputs": {
                    "train": str(output_train),
                    "eval": str(output_eval) if output_eval else None,
                },
                **summary,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
