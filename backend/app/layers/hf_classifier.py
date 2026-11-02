"""Hugging Face Inference API classifiers. Timeouts and errors return None (fail-secure)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

_PHISH_POSITIVE = ("phish", "spam", "malicious", "fraud")
_PHISH_NEGATIVE = ("ham", "legit", "benign", "safe")
_INJECT_POSITIVE = ("inject", "jailbreak", "unsafe", "attack")
_INJECT_NEGATIVE = ("safe", "benign", "legit", "clean", "ham")


def hf_configured() -> bool:
    settings = get_settings()
    return bool(settings.use_hf_classifier and settings.hf_token)


async def phishing_probability(text: str, *, client: httpx.AsyncClient | None) -> float | None:
    settings = get_settings()
    return await _score(
        text,
        client=client,
        model=settings.hf_phishing_model,
        positive=_PHISH_POSITIVE,
        negative=_PHISH_NEGATIVE,
    )


async def injection_probability(text: str, *, client: httpx.AsyncClient | None) -> float | None:
    settings = get_settings()
    return await _score(
        text,
        client=client,
        model=settings.hf_injection_model,
        positive=_INJECT_POSITIVE,
        negative=_INJECT_NEGATIVE,
    )


async def _score(
    text: str,
    *,
    client: httpx.AsyncClient | None,
    model: str,
    positive: tuple[str, ...],
    negative: tuple[str, ...],
) -> float | None:
    settings = get_settings()
    clipped = (text or "").strip()
    if not clipped or client is None or not hf_configured() or not model:
        return None
    url = f"{settings.hf_inference_url.rstrip('/')}/{model.lstrip('/')}"
    timeout_s = max(0.2, settings.hf_classifier_timeout_ms / 1000.0)
    try:
        response = await client.post(
            url,
            headers={
                "authorization": f"Bearer {settings.hf_token}",
                "content-type": "application/json",
            },
            json={"inputs": clipped[:2000], "options": {"wait_for_model": False}},
            timeout=timeout_s,
        )
        if response.status_code >= 400:
            logger.info("Hugging Face classifier HTTP %s", response.status_code)
            return None
        payload = response.json()
    except Exception as exc:
        logger.info("Hugging Face classifier failed: %s", type(exc).__name__)
        return None
    return _probability_from_payload(payload, positive=positive, negative=negative)


def _probability_from_payload(
    payload: Any,
    *,
    positive: tuple[str, ...],
    negative: tuple[str, ...],
) -> float | None:
    rows = _label_rows(payload)
    if not rows:
        return None
    best_pos: float | None = None
    best_neg: float | None = None
    for label, score in rows:
        token = label.lower()
        if any(part in token for part in positive) or token in {"label_1", "1"}:
            best_pos = score if best_pos is None else max(best_pos, score)
        elif any(part in token for part in negative) or token in {"label_0", "0"}:
            best_neg = score if best_neg is None else max(best_neg, score)
    if best_pos is not None:
        return best_pos
    if best_neg is not None:
        return round(1.0 - best_neg, 6)
    return None


def _label_rows(payload: Any) -> list[tuple[str, float]]:
    if isinstance(payload, dict) and payload.get("error"):
        return []
    current = payload
    while isinstance(current, list) and current and isinstance(current[0], list):
        current = current[0]
    if not isinstance(current, list):
        return []
    rows: list[tuple[str, float]] = []
    for item in current:
        if not isinstance(item, dict):
            continue
        try:
            rows.append((str(item.get("label") or ""), float(item.get("score") or 0.0)))
        except (TypeError, ValueError):
            continue
    return rows
