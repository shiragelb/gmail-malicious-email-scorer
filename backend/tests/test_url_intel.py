"""Threat-intelligence matching from the testing plan."""

from __future__ import annotations

import httpx
import pytest

from app.layers.url_intel import screen_urls
from app.pipeline import analyze_email
from app.schemas import EmailInput, UrlIntelReport
from app.scenarios import SCENARIOS


def _handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    if host == "urlhaus-api.abuse.ch":
        return httpx.Response(
            200,
            json={"query_status": "ok", "threat": "malware_download", "url": "http://malicious-test-url.com"},
        )
    if host == "checkurl.phishtank.com":
        return httpx.Response(200, json={"results": {"in_database": True, "verified": True, "valid": True}})
    if host == "safebrowsing.googleapis.com":
        return httpx.Response(200, json={"matches": [{"threatType": "MALWARE", "threat": {"url": "http://malicious-test-url.com"}}]})
    return httpx.Response(404, json={"error": "unexpected host"})


@pytest.mark.asyncio
async def test_threat_intel_match_adds_penalty_points():
    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        report = await screen_urls(["http://malicious-test-url.com"], client=client)

    assert report.matched is True
    assert report.penalty_points > 0
    assert any(match.threat == "malware_download" for match in report.matches)
    assert any("malicious-test-url.com" in match.url for match in report.matches)

    benign = EmailInput(
        from_display="Jordan Lee",
        from_address="jordan.lee@gmail.com",
        subject="Thursday",
        body_text="See you Thursday.",
        headers=SCENARIOS[0].email.headers,
    )
    listed = benign.model_copy(update={"body_text": "See you Thursday. http://malicious-test-url.com"})

    async def no_hits(urls, **kwargs):
        del urls, kwargs
        return UrlIntelReport()

    async def mocked_hit(urls, **kwargs):
        del urls, kwargs
        return report

    clean = await analyze_email(benign, url_screen=no_hits)
    dirty = await analyze_email(listed, url_screen=mocked_hit)
    assert dirty.score > clean.score
    assert dirty.score - clean.score >= min(report.penalty_points, 40)


@pytest.mark.asyncio
async def test_reserved_test_url_still_counts_when_the_feed_has_no_record():
    def empty_urlhaus(request: httpx.Request) -> httpx.Response:
        if request.url.host == "urlhaus-api.abuse.ch":
            return httpx.Response(200, json={"query_status": "no_results"})
        return httpx.Response(404)

    transport = httpx.MockTransport(empty_urlhaus)
    async with httpx.AsyncClient(transport=transport) as client:
        report = await screen_urls(["http://malicious-test-url.com/login"], client=client)

    assert report.matched is True
    assert report.penalty_points > 0
    assert any(match.threat == "reserved_test_url" for match in report.matches)


@pytest.mark.asyncio
async def test_feed_timeout_adds_no_penalty():
    def explode(request: httpx.Request) -> httpx.Response:
        del request
        raise httpx.TimeoutException("timed out")

    transport = httpx.MockTransport(explode)
    async with httpx.AsyncClient(transport=transport) as client:
        report = await screen_urls(["http://example.com/status"], client=client)

    assert report.penalty_points == 0
    assert report.matched is False
    assert "urlhaus_error" in report.unavailable
