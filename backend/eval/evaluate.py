"""Offline precision, recall, and two false-positive rates.

CSV columns: label,subject,from_display,from_address,body. Labels are `phish` or `legit`.
Default corpus is corpus_v1.csv (Nazario phishing + Enron legit + smoke templates).

False-positive definitions (benign / legit rows):
  fpr_strict — engine verdict is Malicious
  fpr_alert  — engine verdict is Suspicious or Malicious (sidebar would warn)

Recall / FNR treat Suspicious as a catch on phishing (same as testing.md).
Pass --live to query URLhaus instead of the offline fixture.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import json
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.layers.text_classifier import classify
from app.layers.url_intel import reserved_url_matches, screen_urls
from app.pipeline import analyze_email
from app.privacy import detect_injection
from app.schemas import AttachmentInput, EmailInput, UrlIntelReport

HERE = Path(__file__).resolve().parent
SAMPLE = HERE / "sample_emails.csv"
CORPUS = HERE / "corpus_v1.csv"
ATTACKS = HERE / "attack_cases.json"
RESULTS = HERE / "eval_results.json"


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
        "true_positive": float(true_positive),
        "true_negative": float(true_negative),
        "false_positive": float(false_positive),
        "false_negative": float(false_negative),
    }


async def _offline_screen(urls: list[str], **kwargs) -> UrlIntelReport:
    del kwargs
    return UrlIntelReport(matches=reserved_url_matches(urls), checked=list(urls))


async def evaluate_csv(path: Path = SAMPLE, *, live: bool = False) -> dict[str, dict[str, float]]:
    rows = load_rows(path)
    labels = [row["label"].strip().lower() == "phish" for row in rows]
    text_predictions: list[bool] = []
    engine_alert: list[bool] = []
    engine_strict: list[bool] = []
    screen = screen_urls if live else _offline_screen
    for row in rows:
        assessment = classify(row.get("subject", ""), row.get("body", ""))
        text_predictions.append(assessment.is_phishing)
        result = await analyze_email(
            EmailInput(
                subject=row.get("subject", ""),
                from_display=row.get("from_display", ""),
                from_address=row.get("from_address", "") or "unknown@invalid.example",
                body_text=row.get("body", ""),
            ),
            url_screen=screen,
        )
        engine_alert.append(result.verdict != "Safe")
        engine_strict.append(result.verdict == "Malicious")
    text = rates(labels, text_predictions)
    alert = rates(labels, engine_alert)
    strict = rates(labels, engine_strict)
    engine = dict(alert)
    engine["fpr_alert"] = alert["fpr"]
    engine["fpr_strict"] = strict["fpr"]
    text["fpr_alert"] = text["fpr"]
    text["fpr_strict"] = text["fpr"]
    return {
        "text": text,
        "engine": engine,
        "dataset": {
            "path": str(path),
            "phish": float(sum(labels)),
            "legit": float(len(labels) - sum(labels)),
            "n": float(len(labels)),
        },
    }


def _hit_rate(hits: list[bool]) -> dict[str, float]:
    total = len(hits) or 1
    detected = sum(hits)
    return {"detected": float(detected), "total": float(len(hits)), "rate": detected / total}


async def evaluate_attacks(path: Path = ATTACKS) -> dict[str, dict[str, float]]:
    cases = json.loads(path.read_text(encoding="utf-8"))
    url_hits: list[bool] = []
    for case in cases.get("urls", []):
        result = await analyze_email(
            EmailInput(
                subject=case["subject"],
                from_display=case.get("from_display", ""),
                from_address=case.get("from_address", "attacker@example.com"),
                body_text=case["body"],
            ),
            url_screen=_offline_screen,
        )
        url_hits.append(result.verdict != "Safe")

    injection_hits: list[bool] = []
    for case in cases.get("injection", []):
        body = case["body"]
        result = await analyze_email(
            EmailInput(
                subject=case["subject"],
                from_display=case.get("from_display", ""),
                from_address=case.get("from_address", "attacker@example.com"),
                body_text=body,
            ),
            url_screen=_offline_screen,
        )
        injection_hits.append(detect_injection(body).matched)

    office_hits: list[bool] = []
    for case in cases.get("office", []):
        fixture = HERE / case["file"]
        raw = fixture.read_bytes()
        attachment = AttachmentInput(
            name=case["name"],
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            size=len(raw),
            content_b64=base64.b64encode(raw).decode("ascii"),
        )
        result = await analyze_email(
            EmailInput(
                subject="See attached",
                from_display="Finance",
                from_address="finance@contoso.com",
                body_text="The spreadsheet is attached.",
                attachments=[attachment],
            ),
            url_screen=_offline_screen,
        )
        finding_codes: set[str] = set()
        for report in result.layers.get("attachments") or []:
            if not isinstance(report, dict):
                continue
            for finding in report.get("findings") or []:
                if isinstance(finding, dict) and finding.get("code"):
                    finding_codes.add(str(finding["code"]))
            if report.get("active"):
                finding_codes.add("active")
        expect = case.get("expect")
        if expect == "clean":
            office_hits.append("office_dde" not in finding_codes and "office_macro" not in finding_codes)
        else:
            office_hits.append(expect in finding_codes or "active" in finding_codes)

    return {
        "url": _hit_rate(url_hits),
        "injection": _hit_rate(injection_hits),
        "office": _hit_rate(office_hits),
    }


def _print_rates(name: str, metrics: dict[str, float]) -> None:
    fpr_strict = metrics.get("fpr_strict", metrics["fpr"])
    fpr_alert = metrics.get("fpr_alert", metrics["fpr"])
    print(
        f"{name:8} accuracy={metrics['accuracy']:.2f} precision={metrics['precision']:.2f} "
        f"recall={metrics['recall']:.2f} fpr_strict={fpr_strict:.2f} fpr_alert={fpr_alert:.2f} "
        f"fnr={metrics['fnr']:.2f} n={int(metrics['support'])}"
    )


def _print_attacks(attacks: dict[str, dict[str, float]]) -> None:
    for name, metrics in attacks.items():
        print(
            f"attack/{name:10} detected={int(metrics['detected'])}/{int(metrics['total'])} "
            f"rate={metrics['rate']:.2f}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Score a labeled email CSV and print detection rates.")
    parser.add_argument("--csv", type=Path, default=CORPUS if CORPUS.is_file() else SAMPLE)
    parser.add_argument("--live", action="store_true", help="Query live threat feeds instead of the offline fixture.")
    parser.add_argument("--skip-attacks", action="store_true")
    parser.add_argument("--out", type=Path, default=RESULTS)
    args = parser.parse_args()
    metrics = asyncio.run(evaluate_csv(args.csv, live=args.live))
    attacks = {} if args.skip_attacks else asyncio.run(evaluate_attacks())
    _print_rates("text", metrics["text"])
    _print_rates("engine", metrics["engine"])
    if attacks:
        _print_attacks(attacks)
    payload = {**metrics, "attacks": attacks, "live": args.live}
    args.out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
