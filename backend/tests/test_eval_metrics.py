"""Dataset metrics stay inside the testing plan's false-positive and false-negative goals."""

from pathlib import Path

import pytest

from eval.evaluate import SAMPLE, evaluate_csv


@pytest.mark.asyncio
async def test_sample_dataset_false_positive_and_false_negative_rates():
    assert Path(SAMPLE).exists()
    metrics = await evaluate_csv(SAMPLE, live=False)
    for layer in ("text", "engine"):
        assert metrics[layer]["fpr"] <= 0.15
        assert metrics[layer]["fnr"] <= 0.15
        assert metrics[layer]["accuracy"] >= 0.85
        assert metrics[layer]["precision"] >= 0.85
        assert metrics[layer]["recall"] >= 0.85
