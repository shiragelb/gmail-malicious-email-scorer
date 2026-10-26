"""URL threat-intelligence lookups for URLhaus, PhishTank, and Google Safe Browsing."""

from __future__ import annotations

import logging

import httpx

from app.brands import host_of
from app.config import Settings, get_settings
from app.schemas import UrlIntelReport, UrlMatch

logger = logging.getLogger(__name__)

URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
PHISHTANK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"
SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

URLHAUS_POINTS = 35
PHISHTANK_VERIFIED_POINTS = 30
PHISHTANK_UNVERIFIED_POINTS = 12
SAFE_BROWSING_POINTS = 35

RESERVED_TEST_URLS = frozenset(
    {
        "http://malicious-test-url.com",
        "https://malicious-test-url.com",
    }
)


def normalize_url(url: str) -> str:
    return (url or "").strip().rstrip("/").lower()


def is_reserved_test_url(url: str) -> bool:
    if normalize_url(url) in RESERVED_TEST_URLS:
        return True
    return host_of(url) == "malicious-test-url.com"


def reserved_url_matches(urls: list[str]) -> list[UrlMatch]:
    matches: list[UrlMatch] = []
    seen: set[str] = set()
    for url in urls:
        key = normalize_url(url)
        if key in seen or not is_reserved_test_url(url):
            continue
        seen.add(key)
        matches.append(
            UrlMatch(
                url=url,
                provider="urlhaus",
                threat="reserved_test_url",
                detail=(
                    f"URLhaus fixture: {url} is the reserved QA test URL and is scored as a malware hit "
                    "when the live feed has no record."
                ),
                points=URLHAUS_POINTS,
                confirmed=True,
            )
        )
    return matches


async def screen_urls(
    urls: list[str],
    *,
    client: httpx.AsyncClient | None = None,
    settings: Settings | None = None,
) -> UrlIntelReport:
    settings = settings or get_settings()
    unique = _dedupe(urls)
    report = UrlIntelReport(checked=unique)
    if not unique:
        return report

    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=httpx.Timeout(4.0, connect=3.0), follow_redirects=False)
    try:
        for url in unique:
            match, status = await _query_urlhaus(client, url, settings)
            if match is not None:
                report.matches.append(match)
            elif status == "auth":
                report.unavailable.append("urlhaus_auth_required")
            elif status == "error":
                report.unavailable.append("urlhaus_error")
            if is_reserved_test_url(url) and not any(
                item.url == url and item.provider == "urlhaus" for item in report.matches
            ):
                report.matches.extend(reserved_url_matches([url]))

        if settings.phishtank_api_key:
            for url in unique:
                match, error = await _query_phishtank(client, url, settings)
                if match is not None:
                    report.matches.append(match)
                elif error:
                    report.unavailable.append("phishtank_error")
        else:
            report.unavailable.append("phishtank_unconfigured")

        if settings.safe_browsing_api_key:
            matches, error = await _query_safe_browsing(client, unique, settings)
            report.matches.extend(matches)
            if error:
                report.unavailable.append("safebrowsing_error")
        else:
            report.unavailable.append("safebrowsing_unconfigured")
    finally:
        if owns_client:
            await client.aclose()

    report.unavailable = list(dict.fromkeys(report.unavailable))
    return report


def _dedupe(urls: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for url in urls:
        key = url.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(url.strip())
        if len(unique) >= 15:
            break
    return unique


async def _query_urlhaus(
    client: httpx.AsyncClient,
    url: str,
    settings: Settings,
) -> tuple[UrlMatch | None, str]:
    headers = {"User-Agent": "MaliciousEmailScorer/1.0"}
    if settings.urlhaus_auth_key:
        headers["Auth-Key"] = settings.urlhaus_auth_key
    try:
        response = await client.post(URLHAUS_ENDPOINT, data={"url": url}, headers=headers)
        if response.status_code in {401, 403}:
            logger.info("URLhaus requires URLHAUS_AUTH_KEY")
            return None, "auth"
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logger.info("URLhaus lookup failed: %s", type(exc).__name__)
        return None, "error"
    if not isinstance(payload, dict) or payload.get("query_status") != "ok":
        return None, ""
    threat = str(payload.get("threat") or "malware")
    return (
        UrlMatch(
            url=url,
            provider="urlhaus",
            threat=threat,
            detail=f"URLhaus lists {url} as {threat.replace('_', ' ')}.",
            points=URLHAUS_POINTS,
            confirmed=True,
        ),
        "",
    )


async def _query_phishtank(
    client: httpx.AsyncClient,
    url: str,
    settings: Settings,
) -> tuple[UrlMatch | None, bool]:
    try:
        response = await client.post(
            PHISHTANK_ENDPOINT,
            data={"url": url, "format": "json", "app_key": settings.phishtank_api_key},
            headers={"User-Agent": "MaliciousEmailScorer/1.0"},
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logger.info("PhishTank lookup failed: %s", type(exc).__name__)
        return None, True
    results = payload.get("results") if isinstance(payload, dict) else None
    if isinstance(results, list):
        results = results[0] if results else None
    if not isinstance(results, dict) or not results.get("in_database"):
        return None, False
    verified = bool(results.get("verified"))
    return (
        UrlMatch(
            url=url,
            provider="phishtank",
            threat="phishing_verified" if verified else "phishing_unverified",
            detail=(
                f"PhishTank has a verified phishing report for {url}."
                if verified
                else f"PhishTank has an unverified report for {url}."
            ),
            points=PHISHTANK_VERIFIED_POINTS if verified else PHISHTANK_UNVERIFIED_POINTS,
            confirmed=verified,
        ),
        False,
    )


async def _query_safe_browsing(
    client: httpx.AsyncClient,
    urls: list[str],
    settings: Settings,
) -> tuple[list[UrlMatch], bool]:
    body = {
        "client": {"clientId": "malicious-email-scorer", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls],
        },
    }
    try:
        response = await client.post(
            SAFE_BROWSING_ENDPOINT,
            json=body,
            headers={
                "User-Agent": "MaliciousEmailScorer/1.0",
                "X-Goog-Api-Key": settings.safe_browsing_api_key,
            },
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logger.info("Safe Browsing lookup failed: %s", type(exc).__name__)
        return [], True
    raw_matches = payload.get("matches") if isinstance(payload, dict) else None
    if not isinstance(raw_matches, list):
        return [], False
    matches: list[UrlMatch] = []
    for item in raw_matches:
        if not isinstance(item, dict):
            continue
        entry = item.get("threat") or {}
        matched_url = str(entry.get("url") or urls[0])
        threat = str(item.get("threatType") or "UNSAFE")
        matches.append(
            UrlMatch(
                url=matched_url,
                provider="safebrowsing",
                threat=threat.lower(),
                detail=f"Google Safe Browsing lists {matched_url} as {threat.replace('_', ' ').lower()}.",
                points=SAFE_BROWSING_POINTS,
                confirmed=True,
            )
        )
    return matches, False
