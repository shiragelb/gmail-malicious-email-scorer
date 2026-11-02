"""The per-instance daily ledger pauses optional pipelines and keeps local scoring."""

from __future__ import annotations

import json

import httpx
import pytest

from app.budget import estimate_claude_cost, ledger, reset_ledger
from app.config import get_settings
from app.layers.meta_analyst import SYSTEM_PROMPT, refine
from app.layers.onnx_classifier import onnx_probability
from app.pipeline import analyze_email
from app.schemas import EmailInput
from app.scoring import ScoreDecision


def test_reserve_hits_the_dollar_cap():
    reset_ledger()
    book = ledger()
    assert book.reserve("claude", 0.6) is True
    assert book.reserve("deep_scan", 0.5) is False
    assert book.reserve("onnx", 0.0) is True
    assert book.optional_paused is False
    assert book.reserve("deep_scan", 0.4) is True
    assert book.optional_paused is True
    assert book.reserve("onnx", 0.0) is False
    assert book.reserve("claude", 0.01) is False


def test_release_returns_budget():
    reset_ledger()
    book = ledger()
    assert book.reserve("claude", 1.0) is True
    book.release(1.0)
    assert book.optional_paused is False
    assert book.reserve("claude", 0.2) is True


@pytest.mark.asyncio
async def test_budget_skips_claude_and_keeps_the_local_score(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-used")
    get_settings.cache_clear()
    reset_ledger()
    ledger().reserve("fill", 1.0)

    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, json={"content": [{"type": "text", "text": '{"score": 0}'}]})

    local = ScoreDecision(score=90, verdict="Malicious", band="confirmed", summary="Listed.")
    email = EmailInput(subject="Hi", from_address="a@example.com", body_text="Hello")
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        decision, engine = await refine(local, email, "Hello", client=client)

    assert called["n"] == 0
    assert engine == "local"
    assert decision.score == 90
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_budget_skips_onnx_and_lexical_score_still_returns(monkeypatch):
    monkeypatch.setenv("USE_ONNX_CLASSIFIER", "true")
    monkeypatch.setenv("ONNX_MODEL_DIR", "/missing-model")
    get_settings.cache_clear()
    reset_ledger()
    ledger().reserve("fill", 1.0)

    def boom(*args, **kwargs):
        raise AssertionError("ONNX should not run after the cap")

    monkeypatch.setattr("app.layers.onnx_classifier._load_session", boom)
    assert onnx_probability("please reset your password immediately") is None

    result = await analyze_email(
        EmailInput(
            subject="Reset your password",
            from_display="Acme Widgets",
            from_address="help@acme-widgets.test",
            body_text="Hi, please reset your password here: https://acme-widgets.test/account/reset",
        )
    )
    assert result.verdict == "Safe"
    assert result.layers["text"]["model"] == "lexical-v1"
    get_settings.cache_clear()


def test_claude_cost_estimate_is_positive():
    cost = estimate_claude_cost(SYSTEM_PROMPT, json.dumps({"hello": "world"}), max_tokens=400)
    assert cost > 0
    assert cost < 0.05
