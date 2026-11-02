"""Prompt-injection check: regex always wins; Hugging Face is an advisor that cannot clear a hit."""

from __future__ import annotations

import httpx

from app.config import get_settings
from app.layers.hf_classifier import injection_probability
from app.privacy import InjectionHit, detect_injection
from app.schemas import Finding

INJECTION_NOTE = (
    "The message contains instructions aimed at a language model. "
    "Claude was not given this email. The local score stands, and no action was taken."
)


def injection_finding() -> Finding:
    return Finding(
        layer="correlation",
        code="prompt_injection",
        polarity="note",
        text=INJECTION_NOTE,
        points=0,
    )


async def assess_injection(
    *raw_parts: str,
    masked_text: str = "",
    client: httpx.AsyncClient | None = None,
) -> InjectionHit:
    hit = detect_injection(*raw_parts)
    if hit.matched:
        return hit
    score = await injection_probability(masked_text, client=client)
    settings = get_settings()
    if score is not None and score >= settings.hf_injection_threshold:
        return InjectionHit(True, "hf-classifier")
    return InjectionHit(False)
