"""Domain age calculation from the testing plan."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.config import get_settings
from app.layers import domain_age
from app.layers.domain_age import assess_domain_age
from app.pipeline import analyze_email
from app.schemas import EmailInput


def test_domain_registered_five_days_ago_is_new():
    now = datetime(2026, 10, 25, tzinfo=timezone.utc)
    result = assess_domain_age(now - timedelta(days=5), domain="new-example.com", now=now)
    assert result.is_new_domain is True
    assert result.age_days == 5
    assert result.risk_weight == "high"


def test_domain_registered_five_years_ago_is_not_new():
    now = datetime(2026, 10, 25, tzinfo=timezone.utc)
    result = assess_domain_age(now - timedelta(days=5 * 365), domain="old-example.com", now=now)
    assert result.is_new_domain is False
    assert result.risk_weight == "none"


def test_unknown_creation_date_is_not_treated_as_new():
    result = assess_domain_age(None, domain="example.com")
    assert result.is_new_domain is False
    assert result.points == 0


@pytest.mark.asyncio
async def test_pipeline_flags_a_five_day_old_sender_domain(monkeypatch):
    monkeypatch.setenv("ENABLE_WHOIS", "true")
    get_settings.cache_clear()
    created = datetime.now(timezone.utc) - timedelta(days=5)
    monkeypatch.setattr(domain_age, "whois_available", lambda: True)
    monkeypatch.setattr(domain_age, "lookup_creation_date", lambda domain: created)

    result = await analyze_email(
        EmailInput(
            from_display="Ada Lovelace",
            from_address="ada@new-example.com",
            subject="Hello",
            body_text="Just saying hello.",
        )
    )
    assert result.layers["identity"]["is_new_domain"] is True
    assert result.layers["identity"]["sender_domain_age_days"] == 5
    blob = " ".join(reason.text for reason in result.reasons).lower()
    assert "days" not in blob
    assert "very new" in blob


@pytest.mark.asyncio
async def test_old_sender_domain_is_not_explained_in_years(monkeypatch):
    monkeypatch.setenv("ENABLE_WHOIS", "true")
    get_settings.cache_clear()
    created = datetime.now(timezone.utc) - timedelta(days=16 * 365)
    monkeypatch.setattr(domain_age, "whois_available", lambda: True)
    monkeypatch.setattr(domain_age, "lookup_creation_date", lambda domain: created)

    result = await analyze_email(
        EmailInput(
            from_display="Duolingo",
            from_address="hello@duolingo.com",
            subject="Keep it up",
            body_text="Your 5 minute lesson is waiting.",
            headers={
                "Authentication-Results": (
                    "mx.google.com; spf=pass smtp.mailfrom=hello@duolingo.com; "
                    "dkim=pass header.i=@duolingo.com; dmarc=pass header.from=duolingo.com"
                )
            },
        )
    )
    blob = " ".join([result.summary, *[reason.text for reason in result.reasons]]).lower()
    assert result.verdict == "Safe"
    assert "year" not in blob
    assert "registered" not in blob
    assert "spf" not in blob
    assert "dkim" not in blob
    assert "dmarc" not in blob
    assert "really came from" in blob
    assert result.reasons[0].text != result.reasons[-1].text or len(result.reasons) == 1
