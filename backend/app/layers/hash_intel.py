"""MalwareBazaar SHA-256 lookups. Only the hash leaves the machine, never the file bytes."""

from __future__ import annotations

import logging

import httpx

from app.config import Settings, get_settings
from app.http_retry import request_with_retries
from app.schemas import UrlMatch

logger = logging.getLogger(__name__)

MALWAREBAZAAR_ENDPOINT = "https://mb-api.abuse.ch/api/v1/"
MALWAREBAZAAR_POINTS = 35


async def lookup_hashes(
    hashes: list[str],
    *,
    client: httpx.AsyncClient | None = None,
    settings: Settings | None = None,
) -> tuple[list[UrlMatch], list[str]]:
    settings = settings or get_settings()
    unique = _dedupe(hashes)
    matches: list[UrlMatch] = []
    unavailable: list[str] = []
    if not unique:
        return matches, unavailable
    if not settings.urlhaus_auth_key:
        unavailable.append("malwarebazaar_unconfigured")
        return matches, unavailable

    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=httpx.Timeout(4.0, connect=3.0), follow_redirects=False)
    try:
        for digest in unique:
            match, status = await _query_malwarebazaar(client, digest, settings)
            if match is not None:
                matches.append(match)
            elif status == "auth":
                unavailable.append("malwarebazaar_auth_required")
            elif status == "error":
                unavailable.append("malwarebazaar_error")
    finally:
        if owns_client:
            await client.aclose()
    return matches, list(dict.fromkeys(unavailable))


async def _query_malwarebazaar(
    client: httpx.AsyncClient,
    digest: str,
    settings: Settings,
) -> tuple[UrlMatch | None, str]:
    headers = {
        "User-Agent": "MaliciousEmailScorer/1.0",
        "Auth-Key": settings.urlhaus_auth_key,
    }
    try:
        response = await request_with_retries(
            client,
            "POST",
            MALWAREBAZAAR_ENDPOINT,
            data={"query": "get_info", "hash": digest},
            headers=headers,
        )
        if response.status_code in {401, 403}:
            logger.info("MalwareBazaar requires a valid abuse.ch Auth-Key")
            return None, "auth"
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logger.info("MalwareBazaar lookup failed: %s", type(exc).__name__)
        return None, "error"

    if not isinstance(payload, dict):
        return None, "error"
    status = str(payload.get("query_status") or "")
    if status in {"hash_not_found", "no_results", "illegal_hash"}:
        return None, ""
    if status != "ok":
        return None, "error" if status else ""

    data = payload.get("data")
    first = data[0] if isinstance(data, list) and data else data if isinstance(data, dict) else {}
    family = ""
    if isinstance(first, dict):
        family = str(first.get("signature") or first.get("malware") or first.get("file_type") or "").strip()
    threat = family or "malware"
    detail = (
        f"MalwareBazaar lists the attachment hash {digest[:12]}… as {threat}."
        if family
        else f"MalwareBazaar lists the attachment hash {digest[:12]}… as known malware."
    )
    return (
        UrlMatch(
            url=f"sha256:{digest}",
            provider="malwarebazaar",
            threat=threat.lower().replace(" ", "_"),
            detail=detail,
            points=MALWAREBAZAAR_POINTS,
            confirmed=True,
        ),
        "",
    )


def _dedupe(hashes: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for item in hashes:
        digest = (item or "").strip().lower()
        if len(digest) != 64 or digest in seen:
            continue
        if any(ch not in "0123456789abcdef" for ch in digest):
            continue
        seen.add(digest)
        unique.append(digest)
        if len(unique) >= 10:
            break
    return unique
