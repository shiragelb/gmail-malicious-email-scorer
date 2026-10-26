"""Header fixtures from tier 3, scored without live feeds."""

from __future__ import annotations

import pytest

from app.pipeline import analyze_email
from app.schemas import EmailInput
from eval.vectors import HEADER_CASES


@pytest.mark.asyncio
@pytest.mark.parametrize("case", HEADER_CASES, ids=[case["id"] for case in HEADER_CASES])
async def test_header_fixture_lands_in_range(case):
    result = await analyze_email(EmailInput.model_validate(case["email"]))
    assert case["min_score"] <= result.score <= case["max_score"]
    assert result.verdict == case["expect_verdict"]
