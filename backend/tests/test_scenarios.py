"""The three end-to-end score ranges from the testing plan."""

from __future__ import annotations

import pytest

from app.pipeline import analyze_email
from app.scenarios import SCENARIOS
from app.scoring import ScoreDecision, apply_guardrails


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", SCENARIOS, ids=[scenario.id for scenario in SCENARIOS])
async def test_qa_scenario_lands_in_its_score_range(scenario):
    result = await analyze_email(scenario.email)
    assert scenario.expected_min <= result.score <= scenario.expected_max
    assert result.verdict == scenario.expected_verdict
    assert result.reasons
    assert result.mitigations


@pytest.mark.asyncio
async def test_scenario_reasons_match_the_story():
    results = {scenario.id: await analyze_email(scenario.email) for scenario in SCENARIOS}
    safe = " ".join(reason.text for reason in results["A"].reasons)
    malicious = " ".join(reason.text for reason in results["B"].reasons)
    suspicious = " ".join(reason.text for reason in results["C"].reasons)

    assert "really came from" in safe.lower()
    assert "could not prove" in malicious.lower()
    assert "Google" in malicious
    assert "security list" in malicious.lower()
    assert "password" in suspicious.lower()
    assert "fake" in suspicious.lower()
    assert "spf" not in safe.lower()
    assert "registered" not in safe.lower()
    assert results["A"].layers["meta"]["band"] == "trusted"
    assert results["B"].layers["meta"]["band"] == "confirmed"
    assert results["C"].layers["meta"]["band"] == "semantic"


def test_language_model_cannot_mark_clean_mail_malicious():
    local = ScoreDecision(score=2, verdict="Safe", band="trusted", summary="Clean.")
    assert apply_guardrails(local, 99) == 15


def test_language_model_cannot_mark_a_confirmed_hit_safe():
    local = ScoreDecision(score=92, verdict="Malicious", band="confirmed", summary="Listed.")
    assert apply_guardrails(local, 5) == 90
