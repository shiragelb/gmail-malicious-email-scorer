"""ONNX timeouts and missing files fall back to the lexical score."""

from __future__ import annotations

from concurrent.futures import TimeoutError as FuturesTimeoutError

import pytest

from app.config import get_settings
from app.layers.onnx_classifier import onnx_probability
from app.pipeline import analyze_email
from app.schemas import EmailInput


class _TimeoutExecutor:
    def submit(self, fn, *args, **kwargs):
        del fn, args, kwargs

        class _Future:
            def result(self, timeout=None):
                del timeout
                raise FuturesTimeoutError()

        return _Future()


def test_missing_model_returns_none(monkeypatch):
    monkeypatch.setenv("USE_ONNX_CLASSIFIER", "true")
    monkeypatch.setenv("ONNX_MODEL_DIR", "/definitely-missing-onnx-model")
    get_settings.cache_clear()
    assert onnx_probability("urgent password reset") is None
    get_settings.cache_clear()


def test_onnx_timeout_returns_none(monkeypatch):
    monkeypatch.setenv("USE_ONNX_CLASSIFIER", "true")
    monkeypatch.setenv("ONNX_MODEL_DIR", "/tmp/fake-onnx")
    monkeypatch.setenv("ONNX_INFERENCE_TIMEOUT_MS", "50")
    get_settings.cache_clear()

    monkeypatch.setattr("app.layers.onnx_classifier._load_session", lambda model_dir: object())
    monkeypatch.setattr("app.layers.onnx_classifier._executor", _TimeoutExecutor())
    assert onnx_probability("please send gift cards") is None
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_onnx_timeout_keeps_the_lexical_score(monkeypatch):
    monkeypatch.setenv("USE_ONNX_CLASSIFIER", "true")
    monkeypatch.setenv("ONNX_MODEL_DIR", "/tmp/fake-onnx")
    monkeypatch.setenv("ONNX_INFERENCE_TIMEOUT_MS", "50")
    get_settings.cache_clear()

    monkeypatch.setattr("app.layers.onnx_classifier._load_session", lambda model_dir: object())
    monkeypatch.setattr("app.layers.onnx_classifier._executor", _TimeoutExecutor())
    result = await analyze_email(
        EmailInput(
            subject="Reset your password",
            from_display="Acme Widgets",
            from_address="help@acme-widgets.test",
            body_text="Hi, please reset your password here: https://acme-widgets.test/account/reset",
        )
    )
    assert result.verdict == "Safe"
    assert result.score <= 35
    assert result.layers["text"]["transformer_probability"] is None
    get_settings.cache_clear()
