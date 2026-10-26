"""Sender-domain age. The pure calculation is separate from the optional WHOIS lookup."""

from __future__ import annotations

import importlib.util
from datetime import datetime, timezone

from app.config import get_settings
from app.schemas import DomainAgeAssessment


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def assess_domain_age(
    created: datetime | None,
    *,
    domain: str = "",
    now: datetime | None = None,
) -> DomainAgeAssessment:
    """Flag domains younger than the configured window (default 30 days) as new."""
    settings = get_settings()
    if created is None:
        return DomainAgeAssessment(
            domain=domain,
            is_new_domain=False,
            age_days=None,
            risk_weight="unknown",
            points=0,
            reason="",
        )

    created_utc = _as_utc(created)
    now_utc = _as_utc(now or datetime.now(timezone.utc))
    age_days = (now_utc - created_utc).days
    if age_days < 0:
        return DomainAgeAssessment(
            domain=domain,
            is_new_domain=False,
            age_days=None,
            risk_weight="unknown",
            points=0,
            reason="",
        )

    if age_days < settings.new_domain_days:
        return DomainAgeAssessment(
            domain=domain,
            is_new_domain=True,
            age_days=age_days,
            risk_weight="high",
            points=20,
            reason=f"The domain {domain or 'of the sender'} was registered {age_days} days ago.",
        )
    if age_days < settings.young_domain_days:
        return DomainAgeAssessment(
            domain=domain,
            is_new_domain=False,
            age_days=age_days,
            risk_weight="low",
            points=8,
            reason=f"The domain {domain or 'of the sender'} is only {age_days} days old.",
        )
    years = max(1, age_days // 365)
    return DomainAgeAssessment(
        domain=domain,
        is_new_domain=False,
        age_days=age_days,
        risk_weight="none",
        points=0,
        reason=f"The domain {domain or 'of the sender'} has been registered for about {years} years.",
    )


def whois_available() -> bool:
    if not get_settings().enable_whois:
        return False
    return importlib.util.find_spec("whois") is not None


def lookup_creation_date(domain: str) -> datetime | None:
    if not domain or not whois_available():
        return None
    try:
        import whois
    except ImportError:
        return None
    try:
        record = whois.whois(domain)
    except Exception:
        return None
    created = getattr(record, "creation_date", None)
    if isinstance(created, list):
        created = min((item for item in created if isinstance(item, datetime)), default=None)
    if not isinstance(created, datetime):
        return None
    return _as_utc(created)
