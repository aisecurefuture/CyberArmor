#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

import numpy as np
import torch
from datasets import Dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)


@dataclass
class Example:
    text: str
    label: int


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Fine-tune a small transformer for prompt-injection detection (binary classification)."
    )
    p.add_argument("--train-jsonl", required=True, help="Path to training JSONL with fields: text,label")
    p.add_argument("--eval-jsonl", default="", help="Optional eval JSONL with fields: text,label")
    p.add_argument("--model-name", default="distilbert-base-uncased", help="Base model checkpoint")
    p.add_argument("--output-dir", required=True, help="Output directory for fine-tuned model")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--max-length", type=int, default=256)
    p.add_argument("--epochs", type=float, default=3.0)
    p.add_argument("--batch-size", type=int, default=16)
    p.add_argument("--lr", type=float, default=2e-5)
    p.add_argument("--weight-decay", type=float, default=0.01)
    p.add_argument("--warmup-ratio", type=float, default=0.1)
    p.add_argument("--split-ratio", type=float, default=0.1, help="Eval split ratio when eval-jsonl not provided")
    return p.parse_args()


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def load_jsonl(path: Path) -> List[Example]:
    out: List[Example] = []
    with path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            text = str(obj.get("text", "")).strip()
            label = obj.get("label")
            if text == "" or label is None:
                raise ValueError(f"Invalid row at {path}:{idx}. Expected fields: text,label.")
            label_int = int(label)
            if label_int not in (0, 1):
                raise ValueError(f"Invalid label at {path}:{idx}. Expected 0 or 1, got {label_int}.")
            out.append(Example(text=text, label=label_int))
    if not out:
        raise ValueError(f"No usable rows in {path}")
    return out


def split_examples(data: List[Example], ratio: float, seed: int) -> Tuple[List[Example], List[Example]]:
    if not 0.0 < ratio < 0.5:
        raise ValueError("--split-ratio must be in (0.0, 0.5)")
    idxs = list(range(len(data)))
    rng = random.Random(seed)
    rng.shuffle(idxs)
    cut = max(1, int(len(data) * ratio))
    eval_idxs = set(idxs[:cut])
    train = [data[i] for i in range(len(data)) if i not in eval_idxs]
    eval_ = [data[i] for i in range(len(data)) if i in eval_idxs]
    if not train or not eval_:
        raise ValueError("Failed to split train/eval; provide larger dataset or explicit --eval-jsonl.")
    return train, eval_


def build_dataset(examples: List[Example]) -> Dataset:
    return Dataset.from_dict({"text": [e.text for e in examples], "label": [e.label for e in examples]})


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)
    labels = np.asarray(labels)
    preds = np.asarray(preds)
    acc = float((preds == labels).mean())
    tp = int(((preds == 1) & (labels == 1)).sum())
    fp = int(((preds == 1) & (labels == 0)).sum())
    fn = int(((preds == 0) & (labels == 1)).sum())
    precision = float(tp / (tp + fp)) if (tp + fp) else 0.0
    recall = float(tp / (tp + fn)) if (tp + fn) else 0.0
    f1 = float((2 * precision * recall) / (precision + recall)) if (precision + recall) else 0.0
    return {"accuracy": acc, "precision": precision, "recall": recall, "f1": f1}


def main() -> int:
    args = parse_args()
    set_seed(args.seed)

    train_path = Path(args.train_jsonl).resolve()
    eval_path = Path(args.eval_jsonl).resolve() if args.eval_jsonl else None
    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    train_examples = load_jsonl(train_path)
    if eval_path:
        eval_examples = load_jsonl(eval_path)
    else:
        train_examples, eval_examples = split_examples(train_examples, ratio=args.split_ratio, seed=args.seed)

    tokenizer = AutoTokenizer.from_pretrained(args.model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_name,
        num_labels=2,
        id2label={0: "benign", 1: "prompt_injection"},
        label2id={"benign": 0, "prompt_injection": 1},
    )

    train_ds = build_dataset(train_examples)
    eval_ds = build_dataset(eval_examples)

    def tokenize_batch(batch):
        return tokenizer(batch["text"], truncation=True, max_length=args.max_length)

    train_ds = train_ds.map(tokenize_batch, batched=True)
    eval_ds = eval_ds.map(tokenize_batch, batched=True)

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)
    train_args = TrainingArguments(
        output_dir=str(out_dir / "checkpoints"),
        learning_rate=args.lr,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        num_train_epochs=args.epochs,
        weight_decay=args.weight_decay,
        warmup_ratio=args.warmup_ratio,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_strategy="epoch",
        report_to=[],
        seed=args.seed,
    )

    trainer = Trainer(
        model=model,
        args=train_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics,
    )

    trainer.train()
    metrics = trainer.evaluate()

    # Save model + tokenizer in detection-consumable path.
    trainer.save_model(str(out_dir))
    tokenizer.save_pretrained(str(out_dir))

    manifest = {
        "task": "prompt_injection_binary_classification",
        "base_model": args.model_name,
        "positive_label_index": 1,
        "label_map": {"0": "benign", "1": "prompt_injection"},
        "train_rows": len(train_examples),
        "eval_rows": len(eval_examples),
        "metrics": metrics,
        "seed": args.seed,
        "max_length": args.max_length,
    }
    (out_dir / "training_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    print("PROMPT_INJECTION_TRANSFORMER_TRAINING_OK")
    print(json.dumps({"output_dir": str(out_dir), "metrics": metrics}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

