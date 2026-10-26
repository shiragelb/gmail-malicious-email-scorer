"""Treat email text as untrusted data. Redact PII before Claude, detect prompt injection."""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.schemas import EmailInput

# Zero-width, bidi overrides, and other controls that hide instructions from a human
# reader while remaining visible to a model.
_INVISIBLE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
    r"|[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)

_EMAIL = re.compile(r"\b([A-Z0-9._%+\-]+)@([A-Z0-9.\-]+\.[A-Z]{2,})\b", re.IGNORECASE)
_PHONE = re.compile(r"(?<!\d)(?:\+?\d[\s\-()]*){8,15}\d(?!\d)")
_CARD = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", re.IGNORECASE)
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_GREETING_NAME = re.compile(
    r"\b((?:hi|hello|dear|hey)\s+)([A-Z][a-z]{1,30})(\b)",
    re.IGNORECASE,
)

# High-signal jailbreak phrasing. Legitimate mail almost never says these.
_INJECTION = (
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b", re.IGNORECASE),
    re.compile(r"\bignore\s+(?:your\s+)?(?:system|developer)\s+prompt\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\b.{0,40}\b(?:unrestricted|jailbroken|dan)\b", re.IGNORECASE),
    re.compile(r"\b(?:system|developer)\s*:\s*(?:ignore|override|new\s+instructions)\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+(?:the\s+)?(?:safety|security)\s+(?:rules?|policy|policies)\b", re.IGNORECASE),
    re.compile(r"\bthis\s+is\s+(?:a\s+)?(?:system|developer)\s+(?:message|prompt)\b", re.IGNORECASE),
    re.compile(r"</email>\s*(?:system|assistant|developer)\s*:", re.IGNORECASE),
    re.compile(r"\b(?:tool_calls?|function_call|suggested_actions)\b.{0,80}\b(?:run|execute|send|delete)\b", re.IGNORECASE),
    re.compile(r"\bmark\s+(?:this\s+)?(?:email|message)\s+as\s+safe\b.{0,40}\bignore\b", re.IGNORECASE),
    re.compile(r"\bnew\s+instructions?\s*:\s*(?:score|output|return|you must)\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class InjectionHit:
    matched: bool
    pattern: str = ""


def strip_hidden(text: str) -> str:
    if not text:
        return ""
    return _INVISIBLE.sub("", text)


def detect_injection(*parts: str) -> InjectionHit:
    blob = strip_hidden("\n".join(part or "" for part in parts))
    for pattern in _INJECTION:
        match = pattern.search(blob)
        if match:
            return InjectionHit(True, match.group(0)[:80])
    return InjectionHit(False)


def redact(text: str, *, limit: int = 4000) -> str:
    """Keep amounts, dates, hosts, and intent. Mask people, accounts, and phones."""
    value = strip_hidden(text or "")

    def _email(match: re.Match[str]) -> str:
        return f"<user>@{match.group(2)}"

    value = _EMAIL.sub(_email, value)
    value = _IBAN.sub("<account>", value)
    value = _SSN.sub("<id>", value)
    value = _CARD.sub("<card>", value)
    value = _PHONE.sub("<phone>", value)
    value = _GREETING_NAME.sub(lambda m: f"{m.group(1)}<name>{m.group(3)}", value)
    return value[:limit]


def skip_sender(email: EmailInput, skip: frozenset[str]) -> bool:
    if not skip:
        return False
    address = (email.from_address or "").strip().lower()
    domain = address.split("@", 1)[-1] if "@" in address else ""
    return address in skip or domain in skip


def display_safe(text: str, *, limit: int = 300) -> str:
    """Reasons shown in the sidebar must not carry jailbreak text."""
    cleaned = strip_hidden(str(text or "")).strip()
    if detect_injection(cleaned).matched:
        return "The language model returned text that looked like an instruction, so it was dropped."
    return cleaned[:limit]
