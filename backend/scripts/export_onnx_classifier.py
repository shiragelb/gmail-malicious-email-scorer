"""Export a DistilBERT-class phishing checkpoint to ONNX for the Cloud Run image.

Run from a machine (or Docker build stage) that has torch + transformers.
The runtime image copies only the exported files and onnxruntime.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


DEFAULT_MODEL = "aamoshdahal/email-phishing-distilbert-finetuned"


def export(model_id: str, out_dir: Path) -> None:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    out_dir.mkdir(parents=True, exist_ok=True)
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    model.eval()
    dummy = tokenizer(
        "Please verify your account password immediately.",
        return_tensors="pt",
        truncation=True,
        max_length=128,
        padding="max_length",
    )
    torch.onnx.export(
        model,
        (dummy["input_ids"], dummy["attention_mask"]),
        str(out_dir / "model.onnx"),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
            "logits": {0: "batch"},
        },
        opset_version=14,
    )
    tokenizer.save_pretrained(out_dir)
    payload = model.config.to_dict()
    (out_dir / "config.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"exported {model_id} -> {out_dir}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--model",
        default=os.environ.get("ONNX_EXPORT_MODEL", DEFAULT_MODEL),
    )
    args = parser.parse_args()
    export(args.model, args.out)


if __name__ == "__main__":
    main()
