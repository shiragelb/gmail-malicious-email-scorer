"""Offline precision, recall, false-positive, and false-negative rates.

The bundled CSV is a smoke set with the same columns a Kaggle or Nazario export can use:
label,subject,from_display,from_address,body. Labels are `phish` or `legit`.
Pass --live to query URLhaus instead of the offline fixture.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.layers.text_classifier import classify
from app.layers.url_intel import reserved_url_matches, screen_urls
from app.pipeline import analyze_email
from app.schemas import EmailInput, UrlIntelReport

SAMPLE = Path(__file__).resolve().parent / "sample_emails.csv"


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def rates(labels: list[bool], predictions: list[bool]) -> dict[str, float]:
    pairs = list(zip(labels, predictions))
    true_positive = sum(label and predicted for label, predicted in pairs)
    true_negative = sum((not label) and (not predicted) for label, predicted in pairs)
    false_positive = sum((not label) and predicted for label, predicted in pairs)
    false_negative = sum(label and (not predicted) for label, predicted in pairs)
    total = len(pairs) or 1
    precision_denom = true_positive + false_positive
    recall_denom = true_positive + false_negative
    negative_denom = false_positive + true_negative
    return {
        "accuracy": (true_positive + true_negative) / total,
        "precision": true_positive / precision_denom if precision_denom else 0.0,
        "recall": true_positive / recall_denom if recall_denom else 0.0,
        "fpr": false_positive / negative_denom if negative_denom else 0.0,
        "fnr": false_negative / recall_denom if recall_denom else 0.0,
        "support": float(len(pairs)),
    }


async def _offline_screen(urls: list[str], **kwargs) -> UrlIntelReport:
    del kwargs
    return UrlIntelReport(matches=reserved_url_matches(urls), checked=list(urls))


async def evaluate_csv(path: Path = SAMPLE, *, live: bool = False) -> dict[str, dict[str, float]]:
    rows = load_rows(path)
    labels = [row["label"].strip().lower() == "phish" for row in rows]
    text_predictions: list[bool] = []
    engine_predictions: list[bool] = []
    screen = screen_urls if live else _offline_screen
    for row in rows:
        assessment = classify(row["subject"], row["body"])
        text_predictions.append(assessment.is_phishing)
        result = await analyze_email(
            EmailInput(
                subject=row["subject"],
                from_display=row["from_display"],
                from_address=row["from_address"],
                body_text=row["body"],
            ),
            url_screen=screen,
        )
        engine_predictions.append(result.verdict != "Safe")
    return {"text": rates(labels, text_predictions), "engine": rates(labels, engine_predictions)}


def _print_rates(name: str, metrics: dict[str, float]) -> None:
    print(
        f"{name:8} accuracy={metrics['accuracy']:.2f} precision={metrics['precision']:.2f} "
        f"recall={metrics['recall']:.2f} fpr={metrics['fpr']:.2f} fnr={metrics['fnr']:.2f} "
        f"n={int(metrics['support'])}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Score a labeled email CSV and print detection rates.")
    parser.add_argument("--csv", type=Path, default=SAMPLE)
    parser.add_argument("--live", action="store_true", help="Query live threat feeds instead of the offline fixture.")
    args = parser.parse_args()
    metrics = asyncio.run(evaluate_csv(args.csv, live=args.live))
    _print_rates("text", metrics["text"])
    _print_rates("engine", metrics["engine"])


if __name__ == "__main__":
    main()
