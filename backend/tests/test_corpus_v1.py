"""Interview corpus is present and labeled with both classes."""

from pathlib import Path
import csv

from eval.evaluate import CORPUS, SAMPLE


def test_corpus_v1_exists_with_both_labels():
    assert CORPUS.is_file(), "run: python eval/build_corpus.py"
    with CORPUS.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    labels = {row["label"].strip().lower() for row in rows}
    assert "phish" in labels
    assert "legit" in labels
    assert 16 <= len(rows) <= 500
    required = {"label", "subject", "from_display", "from_address", "body"}
    assert required.issubset(rows[0].keys())


def test_sample_smoke_csv_still_present():
    assert Path(SAMPLE).is_file()
