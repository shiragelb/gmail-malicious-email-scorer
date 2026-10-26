"""Lexical phishing classifier, with an optional Hugging Face model as a weak nudge."""

from __future__ import annotations

import logging
import re

from app.config import get_settings
from app.schemas import TextAssessment

logger = logging.getLogger(__name__)

# Advance-fee / inheritance / lottery wording. These are the only text patterns
# that may push a message into the Suspicious band on wording alone.
_SEVERE: tuple[tuple[re.Pattern[str], str, float], ...] = (
    (
        re.compile(
            r"\b(?:grand\s*m(?:a|other)|grand\s*f(?:a|ather)|grandma|grandpa)\b",
            re.IGNORECASE,
        ),
        "The message claims to be from a distant relative.",
        0.55,
    ),
    (
        re.compile(
            r"\b(?:inheritance|next of kin|beneficiary|unclaimed\s+(?:funds?|estate)|late husband)\b",
            re.IGNORECASE,
        ),
        "The message offers an inheritance or unclaimed funds.",
        0.7,
    ),
    (
        re.compile(
            r"\b(?:farm|ranch|cattle|gold\s*mine)s?\b.{0,40}\b(?:alaska|nigeria|dubai)\b",
            re.IGNORECASE,
        ),
        "The message asks for help with a remote farm, ranch, or mine.",
        0.7,
    ),
    (
        re.compile(
            r"\b(?:alaska|nigeria|dubai)\b.{0,40}\b(?:farm|ranch|cattle|gold\s*mine)s?\b",
            re.IGNORECASE,
        ),
        "The message asks for help with a remote farm, ranch, or mine.",
        0.7,
    ),
    (
        re.compile(r"\b(?:you(?:'ve| have)\s+won|lottery\s+winner|jackpot|prize\s+money)\b", re.IGNORECASE),
        "The message claims lottery or prize winnings.",
        0.65,
    ),
    (re.compile(r"\bgift\s+cards?\b", re.IGNORECASE), "The message asks for gift cards.", 0.55),
    (re.compile(r"\bwire\s+transfer\b", re.IGNORECASE), "The message asks for a wire transfer.", 0.55),
    (
        re.compile(r"\b(?:social security|ssn|seed phrase|recovery phrase)\b", re.IGNORECASE),
        "The message asks for a highly sensitive secret.",
        0.7,
    ),
    (
        re.compile(r"\b(?:bitcoin|crypto(?:currency)?\s*wallet)\b.{0,40}\b(?:send|transfer|deposit)\b", re.IGNORECASE),
        "The message asks for a cryptocurrency payment.",
        0.55,
    ),
)

# Ordinary account mail from real companies. This may corroborate a lookalike
# link, but it must not floor the score at Suspicious by itself.
_CREDENTIAL: tuple[tuple[re.Pattern[str], str, float], ...] = (
    (
        re.compile(
            r"\b(?:confirm|verify|update|validate|reset|change)\s+(?:your\s+)?(?:password|passcode|credentials|account|identity)\b",
            re.IGNORECASE,
        ),
        "The message asks the recipient to confirm a password or account.",
        0.28,
    ),
    (
        re.compile(r"\benter\s+your\s+(?:password|credentials)\b", re.IGNORECASE),
        "The message asks the recipient to enter a password.",
        0.28,
    ),
    (
        re.compile(
            r"\b(?:account|mailbox)\b.{0,48}\b(?:suspended|locked|disabled|compromised)\b",
            re.IGNORECASE,
        ),
        "The message threatens to suspend or lock an account.",
        0.22,
    ),
    (
        re.compile(
            r"\b(?:suspended|locked|disabled|compromised)\b.{0,48}\b(?:account|mailbox)\b",
            re.IGNORECASE,
        ),
        "The message threatens to suspend or lock an account.",
        0.22,
    ),
    (
        re.compile(r"\bone[- ]time (?:password|code|pin)\b", re.IGNORECASE),
        "The message asks for a one-time code.",
        0.22,
    ),
)

_MEDIUM: tuple[tuple[re.Pattern[str], str, float], ...] = (
    (re.compile(r"\b(?:urgent|immediately|act now|right away)\b", re.IGNORECASE), "The wording is urgent.", 0.1),
    (re.compile(r"\bwithin\s+\d+\s+(?:hours|minutes)\b", re.IGNORECASE), "The message sets a short deadline.", 0.1),
    (re.compile(r"\b(?:log\s*in|sign\s*in)\b", re.IGNORECASE), "The message uses login language.", 0.06),
)

_HUGE_MONEY = re.compile(
    r"(?:\$|€|£)\s?\d[\d,]{6,}|\b\d[\d,]{6,}\s*(?:usd|dollars?|euros?|million)\b",
    re.IGNORECASE,
)

_pipeline_cache: dict[str, object] = {}


def classify(subject: str, body: str) -> TextAssessment:
    text = f"{subject or ''}\n{body or ''}".strip()
    indicators: list[str] = []
    seen: set[str] = set()
    probability = 0.0
    severe = False
    credential = False

    for pattern, label, weight in _SEVERE:
        if pattern.search(text) and label not in seen:
            seen.add(label)
            indicators.append(label)
            probability += weight
            severe = True
    if _HUGE_MONEY.search(text) and "The message promises a very large sum of money." not in seen:
        if severe or re.search(r"\b(?:claim|beneficiary|transfer|inheritance|won)\b", text, re.IGNORECASE):
            seen.add("The message promises a very large sum of money.")
            indicators.append("The message promises a very large sum of money.")
            probability += 0.45
            severe = True
    if severe and indicators == ["The message claims to be from a distant relative."]:
        # "Grandma" alone is not a scam. Keep the note, drop the Suspicious floor.
        severe = False

    for pattern, label, weight in _CREDENTIAL:
        if pattern.search(text) and label not in seen:
            seen.add(label)
            indicators.append(label)
            probability += weight
            credential = True
    for pattern, label, weight in _MEDIUM:
        if pattern.search(text) and label not in seen:
            seen.add(label)
            indicators.append(label)
            probability += weight

    probability = round(min(1.0, probability), 4)
    model = "lexical-v1"
    remote = _transformer_probability(text)
    if remote is not None:
        model = f"lexical-v1+{get_settings().transformer_model}"
        if severe and remote >= 0.7:
            probability = round(min(1.0, 0.7 * probability + 0.3 * remote), 4)
        elif remote >= 0.8:
            # Hugging Face often flags ordinary password-reset mail. Keep that as a
            # few extra points, never as the reason the message becomes Suspicious.
            probability = round(min(1.0, probability + 0.08), 4)

    if severe:
        points = max(26, round(probability * 28))
    elif credential:
        points = min(12, max(4, round(probability * 14)))
        if remote is not None and remote >= 0.8:
            points = min(12, points + 4)
    else:
        points = round(probability * 8)
        if remote is not None and remote >= 0.9:
            points = min(8, points + 3)

    return TextAssessment(
        phishing_probability=probability,
        is_phishing=severe or credential,
        is_severe=severe,
        points=points,
        indicators=indicators,
        model=model,
        transformer_probability=remote,
    )


def _transformer_probability(text: str) -> float | None:
    settings = get_settings()
    if not settings.use_transformers or not text:
        return None
    try:
        from transformers import pipeline
    except ImportError:
        logger.info("USE_TRANSFORMERS is set but the transformers package is not installed.")
        return None
    try:
        classifier = _pipeline_cache.get(settings.transformer_model)
        if classifier is None:
            classifier = pipeline("text-classification", model=settings.transformer_model)
            _pipeline_cache[settings.transformer_model] = classifier
        result = classifier(text[:2000])[0]
        label = str(result.get("label", "")).lower()
        score = float(result.get("score", 0.0))
    except Exception as exc:
        logger.info("Transformer classification failed: %s", type(exc).__name__)
        return None
    if any(token in label for token in ("phish", "spam", "malicious")) or label in {"label_1", "1"}:
        return score
    if any(token in label for token in ("ham", "legit", "benign", "safe")) or label in {"label_0", "0"}:
        return 1.0 - score
    return None
