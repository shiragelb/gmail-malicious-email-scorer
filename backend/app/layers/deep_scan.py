"""On-demand VirusTotal URL reputation. Never fetches the submitted URL."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.budget import ledger
from app.brands import host_of
from app.config import get_settings
from app.privacy import detect_injection, display_safe, redact
from app.sanitize import prepare_content
from app.schemas import EmailInput, Finding, UrlMatch

logger = logging.getLogger(__name__)

VT_SUBMIT = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS = "https://www.virustotal.com/api/v3/analyses/"
VT_POINTS = 35
SHORTENER_HOSTS = frozenset(
    {
        "bit.ly",
        "bitly.com",
        "t.co",
        "tinyurl.com",
        "tiny.cc",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "rebrand.ly",
        "lnkd.in",
        "shorturl.at",
        "v.gd",
        "rb.gy",
        "t.ly",
        "s.id",
        "adf.ly",
        "trib.al",
        "clck.ru",
        "qr.ae",
    }
)

_cache_lock = threading.Lock()
_analysis_cache: dict[str, tuple[float, str]] = {}


@dataclass(frozen=True)
class ScanItem:
    bare_url: str
    url_hash: str
    analysis_id: str


@dataclass
class UrlReputation:
    bare_url: str
    host: str
    status: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    comment: str = ""


def is_shortener_url(url: str) -> bool:
    host = host_of(url)
    if not host:
        return False
    if host in SHORTENER_HOSTS:
        return True
    return any(host.endswith("." + item) for item in SHORTENER_HOSTS)


def strip_url(url: str) -> str | None:
    raw = (url or "").strip()
    if not raw:
        return None
    parts = urlsplit(raw)
    scheme = (parts.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    port = parts.port
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def url_hash(bare_url: str) -> str:
    return hashlib.sha256(bare_url.encode("utf-8")).hexdigest()


def extract_bare_urls(email: EmailInput, *, limit: int | None = None) -> list[str]:
    from app.layers import file_inspect

    settings = get_settings()
    cap = limit if limit is not None else settings.deep_scan_max_urls
    _, urls = prepare_content(email.body_text, email.body_html)
    file_urls = file_inspect.inspect_attachments(email.attachments).urls
    bare: list[str] = []
    seen: set[str] = set()
    for url in [*urls, *file_urls]:
        stripped = strip_url(url)
        if not stripped or stripped in seen:
            continue
        seen.add(stripped)
        bare.append(stripped)
        if cap > 0 and len(bare) >= cap:
            break
    return bare


def deep_scan_configured() -> bool:
    settings = get_settings()
    return bool(settings.enable_deep_scan and settings.virustotal_api_key)


def mint_scan_token(items: list[ScanItem], *, now: float | None = None) -> str:
    settings = get_settings()
    current = int(now if now is not None else time.time())
    payload = {
        "exp": current + max(60, settings.deep_scan_token_ttl_seconds),
        "items": [{"h": item.url_hash, "a": item.analysis_id} for item in items],
    }
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
    signature = hmac.new(_token_secret().encode("utf-8"), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def parse_scan_token(token: str, *, now: float | None = None) -> list[dict]:
    raw = (token or "").strip()
    if "." not in raw:
        raise ValueError("Invalid scan token")
    body, signature = raw.rsplit(".", 1)
    expected = hmac.new(_token_secret().encode("utf-8"), body.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature.lower()):
        raise ValueError("Invalid scan token")
    padded = body + "=" * (-len(body) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid scan token") from exc
    if not isinstance(payload, dict) or "exp" not in payload or "items" not in payload:
        raise ValueError("Invalid scan token")
    current = int(now if now is not None else time.time())
    try:
        expiry = int(payload["exp"])
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid scan token") from exc
    if expiry < current:
        raise ValueError("Scan token expired")
    items = payload["items"]
    if not isinstance(items, list) or not items:
        raise ValueError("Invalid scan token")
    cleaned: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Invalid scan token")
        url_h = str(item.get("h") or "")
        analysis_id = str(item.get("a") or "")
        if len(url_h) != 64 or not analysis_id:
            raise ValueError("Invalid scan token")
        cleaned.append({"h": url_h, "a": analysis_id})
    return cleaned


async def submit_urls(urls: list[str], *, client: httpx.AsyncClient) -> list[ScanItem]:
    settings = get_settings()
    items: list[ScanItem] = []
    billed = 0
    cost_each = max(0.0, settings.deep_scan_usd_per_url)
    book = ledger()
    for bare in urls:
        cached = _cached_analysis(bare)
        if cached:
            items.append(ScanItem(bare_url=bare, url_hash=url_hash(bare), analysis_id=cached))
            continue
        if not book.reserve("deep_scan", cost_each):
            if not items:
                raise BudgetPaused()
            break
        try:
            analysis_id = await _submit_one(bare, client=client)
        except Exception:
            book.release(cost_each)
            logger.info("VirusTotal submit failed for a URL")
            if not items:
                raise
            break
        billed += 1
        _remember_analysis(bare, analysis_id)
        items.append(ScanItem(bare_url=bare, url_hash=url_hash(bare), analysis_id=analysis_id))
    if not items:
        raise RuntimeError("VirusTotal returned no analyses")
    del billed
    return items


async def poll_analyses(
    token_items: list[dict],
    urls: list[str],
    *,
    client: httpx.AsyncClient,
) -> tuple[str, list[UrlReputation]]:
    by_hash = {url_hash(bare): bare for bare in urls}
    reports: list[UrlReputation] = []
    for item in token_items:
        bare = by_hash.get(item["h"])
        if not bare:
            continue
        payload = await _get_analysis(item["a"], client=client)
        status = str(((payload.get("data") or {}).get("attributes") or {}).get("status") or "")
        if status != "completed":
            return "pending", []
        stats = ((payload.get("data") or {}).get("attributes") or {}).get("stats") or {}
        results = ((payload.get("data") or {}).get("attributes") or {}).get("results") or {}
        comment = _first_engine_result(results)
        reports.append(
            UrlReputation(
                bare_url=bare,
                host=host_of(bare),
                status="completed",
                malicious=_stat(stats, "malicious"),
                suspicious=_stat(stats, "suspicious"),
                harmless=_stat(stats, "harmless"),
                undetected=_stat(stats, "undetected"),
                comment=comment,
            )
        )
    if len(reports) < len(token_items):
        return "pending", []
    return "completed", reports


def interpret_reports(reports: list[UrlReputation]) -> tuple[list[UrlMatch], list[Finding], dict]:
    settings = get_settings()
    threshold = max(1, settings.deep_scan_malicious_threshold)
    matches: list[UrlMatch] = []
    findings: list[Finding] = []
    evidence_urls: list[dict] = []
    for report in reports:
        note = sanitize_vendor_text(report.comment)
        evidence_urls.append(
            {
                "host": report.host,
                "malicious": report.malicious,
                "suspicious": report.suspicious,
                "harmless": report.harmless,
                "undetected": report.undetected,
                "status": report.status,
                **({"note": note} if note else {}),
            }
        )
        if report.malicious >= threshold:
            matches.append(
                UrlMatch(
                    url=report.bare_url,
                    provider="virustotal",
                    threat="multi_engine",
                    detail=(
                        f"VirusTotal: {report.malicious} scanners flagged a link as malicious."
                    ),
                    points=VT_POINTS,
                    confirmed=True,
                )
            )
        else:
            findings.append(
                Finding(
                    layer="url",
                    code="deep_scan_note",
                    polarity="note",
                    text=(
                        "On-demand scanners reviewed a link. "
                        f"{report.malicious} flagged it, which is below the confirmation bar."
                    ),
                    points=0,
                )
            )
    evidence = {"provider": "virustotal", "urls": evidence_urls}
    return matches, findings, evidence


def sanitize_vendor_text(text: str) -> str:
    cleaned = redact(text or "", limit=300)
    if not cleaned or detect_injection(cleaned).matched:
        return ""
    return display_safe(cleaned, limit=200)


def reset_caches() -> None:
    with _cache_lock:
        _analysis_cache.clear()


def _token_secret() -> str:
    settings = get_settings()
    return settings.request_signing_secret or settings.account_token_secret or "dev-deep-scan-token"


def _cached_analysis(bare_url: str) -> str | None:
    now = time.time()
    with _cache_lock:
        expiry, analysis_id = _analysis_cache.get(bare_url, (0.0, ""))
        if expiry > now and analysis_id:
            return analysis_id
        if bare_url in _analysis_cache:
            del _analysis_cache[bare_url]
    return None


def _remember_analysis(bare_url: str, analysis_id: str) -> None:
    ttl = max(60, get_settings().deep_scan_token_ttl_seconds)
    with _cache_lock:
        _analysis_cache[bare_url] = (time.time() + ttl, analysis_id)


async def _submit_one(bare_url: str, *, client: httpx.AsyncClient) -> str:
    settings = get_settings()
    response = await client.post(
        VT_SUBMIT,
        headers={"x-apikey": settings.virustotal_api_key, "content-type": "application/x-www-form-urlencoded"},
        data={"url": bare_url},
        timeout=8.0,
    )
    response.raise_for_status()
    payload = response.json()
    analysis_id = str(((payload.get("data") or {}).get("id") or "")).strip()
    if not analysis_id:
        raise RuntimeError("VirusTotal submit returned no analysis id")
    return analysis_id


async def _get_analysis(analysis_id: str, *, client: httpx.AsyncClient) -> dict:
    settings = get_settings()
    response = await client.get(
        VT_ANALYSIS + analysis_id,
        headers={"x-apikey": settings.virustotal_api_key},
        timeout=8.0,
    )
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


def _stat(stats: dict, key: str) -> int:
    try:
        return max(0, int(stats.get(key) or 0))
    except (TypeError, ValueError):
        return 0


def _first_engine_result(results: object) -> str:
    if not isinstance(results, dict):
        return ""
    for value in results.values():
        if not isinstance(value, dict):
            continue
        result = str(value.get("result") or "").strip()
        if result:
            return result
    return ""


class BudgetPaused(Exception):
    """The daily estimated-spend cap cannot cover this scan."""
