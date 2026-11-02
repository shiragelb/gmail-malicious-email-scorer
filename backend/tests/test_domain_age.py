"""Domain age calculation from the testing plan."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.config import get_settings
from app.layers import domain_age
from app.layers.domain_age import assess_domain_age, reset_cache
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


@pytest.mark.asyncio
async def test_rdap_young_domain_recommends_deep_scan_without_calling_virustotal(monkeypatch):
    monkeypatch.setenv("ENABLE_DOMAIN_AGE", "true")
    monkeypatch.setenv("ENABLE_DEEP_SCAN", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    get_settings.cache_clear()
    reset_cache()
    created = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    seen = {"vt": 0, "rdap": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "virustotal" in url:
            seen["vt"] += 1
            return httpx.Response(500)
        if "rdap.org" in url:
            seen["rdap"] += 1
            return httpx.Response(
                200,
                json={"events": [{"eventAction": "registration", "eventDate": created}]},
            )
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await analyze_email(
            EmailInput(
                from_display="Ada Lovelace",
                from_address="ada@new-example.com",
                subject="Hello",
                body_text="Read https://new-example.com/docs",
            ),
            client=client,
        )

    assert seen["vt"] == 0
    assert seen["rdap"] >= 1
    assert result.layers["identity"]["is_new_domain"] is True
    assert result.deep_scan.recommended is True
    assert result.deep_scan.reason == "new_domain"
    assert result.deep_scan.available is True
    assert result.deep_scan.scan_id == ""
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_unknown_shortener_recommends_deep_scan(monkeypatch):
    monkeypatch.setenv("ENABLE_DEEP_SCAN", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    get_settings.cache_clear()
    result = await analyze_email(
        EmailInput(
            from_display="Jordan Lee",
            from_address="jordan.lee@gmail.com",
            subject="Notes",
            body_text="Thursday works. Details: https://bit.ly/abc123",
            headers={
                "Authentication-Results": (
                    "mx.google.com; spf=pass smtp.mailfrom=jordan.lee@gmail.com; "
                    "dkim=pass header.i=@gmail.com; dmarc=pass header.from=gmail.com"
                )
            },
        )
    )
    assert result.deep_scan.available is True
    assert result.deep_scan.recommended is True
    assert result.deep_scan.reason == "unknown_redirect"
    assert result.deep_scan.scan_id == ""
    get_settings.cache_clear()
