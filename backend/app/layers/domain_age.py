"""Sender-domain age. RDAP is the fast path; WHOIS remains an optional fallback."""

from __future__ import annotations

import importlib.util
import logging
import re
import threading
import time
from datetime import datetime, timezone

import httpx

from app.config import get_settings
from app.schemas import DomainAgeAssessment

logger = logging.getLogger(__name__)

_RDAP_URL = "https://rdap.org/domain/{host}"
_IP_HOST = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_cache_lock = threading.Lock()
_cache: dict[str, tuple[float, datetime | None]] = {}
_MISS = object()


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


def lookups_enabled() -> bool:
    return get_settings().enable_domain_age or whois_available()


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


async def lookup_creation_date_async(domain: str, *, client: httpx.AsyncClient | None = None) -> datetime | None:
    host = (domain or "").strip().lower().strip(".")
    if not host:
        return None
    cached = _cache_get(host)
    if cached is not _MISS:
        return cached  # type: ignore[return-value]
    created: datetime | None = None
    settings = get_settings()
    if settings.enable_domain_age and client is not None and not _IP_HOST.match(host) and ":" not in host:
        created = await _rdap_creation_date(host, client)
    if created is None and whois_available():
        import asyncio

        created = await asyncio.to_thread(lookup_creation_date, host)
    _cache_put(host, created)
    return created


def reset_cache() -> None:
    with _cache_lock:
        _cache.clear()


def _cache_get(host: str):
    now = time.monotonic()
    with _cache_lock:
        expiry, created = _cache.get(host, (0.0, None))
        if expiry > now:
            return created
        if host in _cache:
            del _cache[host]
    return _MISS


def _cache_put(host: str, created: datetime | None) -> None:
    ttl = max(60, get_settings().domain_age_cache_ttl_seconds)
    with _cache_lock:
        _cache[host] = (time.monotonic() + ttl, created)


async def _rdap_creation_date(host: str, client: httpx.AsyncClient) -> datetime | None:
    timeout_s = max(0.2, get_settings().domain_age_timeout_ms / 1000.0)
    try:
        response = await client.get(
            _RDAP_URL.format(host=host),
            timeout=httpx.Timeout(timeout_s, connect=timeout_s),
            follow_redirects=True,
        )
        if response.status_code >= 400:
            return None
        payload = response.json()
    except Exception as exc:
        logger.info("RDAP lookup failed for a domain: %s", type(exc).__name__)
        return None
    if not isinstance(payload, dict):
        return None
    events = payload.get("events") or []
    if not isinstance(events, list):
        return None
    dates: list[datetime] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction") or "").lower()
        if action not in {"registration", "registered"}:
            continue
        parsed = _parse_rdap_date(str(event.get("eventDate") or ""))
        if parsed is not None:
            dates.append(parsed)
    if not dates:
        return None
    return min(dates)


def _parse_rdap_date(value: str) -> datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        try:
            parsed = datetime.strptime(raw[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    return _as_utc(parsed)
