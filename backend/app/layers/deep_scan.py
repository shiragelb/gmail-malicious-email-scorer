"""On-demand VirusTotal URL reputation. Never fetches the submitted URL."""

from __future__ import annotations

import asyncio
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
from app.schemas import AttachmentInput, EmailInput, Finding, UrlMatch

logger = logging.getLogger(__name__)

VT_SUBMIT = "https://www.virustotal.com/api/v3/urls"
VT_URLS = "https://www.virustotal.com/api/v3/urls/"
VT_ANALYSIS = "https://www.virustotal.com/api/v3/analyses/"
VT_FILES = "https://www.virustotal.com/api/v3/files/"
VT_POINTS = 35
SANDBOX_POINTS = 35
SANDBOX_MALICIOUS_TAGS = frozenset(
    {
        "malware",
        "trojan",
        "ransomware",
        "spyware",
        "backdoor",
        "worm",
        "dropper",
        "keylogger",
        "botnet",
        "rootkit",
    }
)
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
    downloaded_sha256: tuple[str, ...] = ()


@dataclass
class SandboxReport:
    sha256: str
    status: str
    malicious: bool = False
    tags: tuple[str, ...] = ()
    verdicts: tuple[str, ...] = ()
    dns_lookups: int = 0
    files_dropped: int = 0
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


def vt_url_id(bare_url: str) -> str:
    return base64.urlsafe_b64encode(bare_url.encode("utf-8")).decode("ascii").rstrip("=")


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


def sandbox_configured() -> bool:
    settings = get_settings()
    return bool(settings.enable_sandbox and settings.virustotal_api_key)


EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SANDBOX_DISCLAIMER = (
    "VirusTotal detonates this known antivirus test file on their machines, not ours. "
    "A cached sandbox report is often 1–2 seconds. A first-time detonation can take several minutes. "
    "This page stays here while it runs."
)


def canned_sandbox_email() -> EmailInput:
    import base64

    return EmailInput(
        subject="Sandbox timing sample",
        from_address="jordan.lee@gmail.com",
        body_text="See https://example.com/notes",
        attachments=[
            AttachmentInput(
                name="eicar.com",
                content_type="application/octet-stream",
                content_b64=base64.b64encode(EICAR_BYTES).decode("ascii"),
            )
        ],
    )


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


async def lookup_url_reports(urls: list[str], *, client: httpx.AsyncClient) -> list[UrlReputation]:
    if not urls:
        return []
    found = await asyncio.gather(*[_get_url_report(bare, client=client) for bare in urls], return_exceptions=True)
    return [item for item in found if isinstance(item, UrlReputation)]


async def wait_for_analyses(
    token_items: list[dict],
    urls: list[str],
    *,
    client: httpx.AsyncClient,
    attempts: int = 2,
    delay_s: float = 0.3,
) -> tuple[str, list[UrlReputation]]:
    last: tuple[str, list[UrlReputation]] = ("pending", [])
    rounds = max(1, attempts)
    for index in range(rounds):
        last = await poll_analyses(token_items, urls, client=client)
        if last[0] != "pending":
            return last
        if index + 1 < rounds:
            await asyncio.sleep(max(0.2, delay_s))
    return last


async def poll_analyses(
    token_items: list[dict],
    urls: list[str],
    *,
    client: httpx.AsyncClient,
) -> tuple[str, list[UrlReputation]]:
    by_hash = {url_hash(bare): bare for bare in urls}
    leftover = [bare for bare in urls if url_hash(bare) not in {item["h"] for item in token_items}]
    reports: list[UrlReputation] = []
    pending = False
    for item in token_items:
        bare = by_hash.get(item["h"])
        if not bare and leftover:
            bare = leftover.pop(0)
        if not bare:
            logger.info("VirusTotal analysis could not be paired with a URL")
            pending = True
            continue
        cached = await _get_url_report(bare, client=client)
        if cached is not None:
            reports.append(cached)
            continue
        payload = await _get_analysis(item["a"], client=client)
        status = str(((payload.get("data") or {}).get("attributes") or {}).get("status") or "").lower()
        if status in {"queued", "in-progress", "inprogress", ""}:
            pending = True
            continue
        if status != "completed":
            logger.info("VirusTotal analysis status=%s", status)
            return "error", reports
        reports.append(_reputation_from_analysis(bare, payload))
    if len(reports) >= len(token_items):
        return "completed", reports
    if pending or len(reports) < len(token_items):
        return "pending", reports
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


def interpret_sandbox(reports: list[SandboxReport]) -> tuple[list[UrlMatch], list[Finding], dict]:
    matches: list[UrlMatch] = []
    findings: list[Finding] = []
    files: list[dict] = []
    forbidden = False
    complete = False
    for report in reports:
        note = sanitize_vendor_text(report.comment)
        files.append(
            {
                "sha256_prefix": report.sha256[:12],
                "status": report.status,
                "malicious": report.malicious,
                "tags": [item for item in (sanitize_vendor_text(tag) for tag in report.tags[:8]) if item],
                "verdicts": [item for item in (sanitize_vendor_text(text) for text in report.verdicts[:6]) if item],
                "dns_lookups": report.dns_lookups,
                "files_dropped": report.files_dropped,
                **({"note": note} if note else {}),
            }
        )
        if report.status == "forbidden":
            forbidden = True
            continue
        if report.status != "complete":
            continue
        complete = True
        if report.malicious:
            matches.append(
                UrlMatch(
                    url="sha256:" + report.sha256[:12],
                    provider="virustotal-sandbox",
                    threat="sandbox",
                    detail="VirusTotal sandbox recorded malicious behavior from a file.",
                    points=SANDBOX_POINTS,
                    confirmed=True,
                )
            )
    if matches:
        findings.append(
            Finding(
                layer="url",
                code="sandbox_hit",
                polarity="risk",
                text="VirusTotal sandbox recorded malicious behavior from a file.",
                points=0,
            )
        )
    elif forbidden and not complete:
        findings.append(
            Finding(
                layer="url",
                code="sandbox_forbidden",
                polarity="note",
                text="VirusTotal sandbox reports are not included on this API key.",
                points=0,
            )
        )
    elif complete:
        findings.append(
            Finding(
                layer="url",
                code="sandbox_note",
                polarity="note",
                text="VirusTotal sandbox reviewed a file. No malicious behavior was recorded.",
                points=0,
            )
        )
    elif reports:
        findings.append(
            Finding(
                layer="url",
                code="sandbox_note",
                polarity="note",
                text="No VirusTotal sandbox report was ready for the linked files.",
                points=0,
            )
        )
    evidence = {"provider": "virustotal", "sandbox": True, "files": files}
    return matches, findings, evidence


async def collect_sandbox(
    email: EmailInput,
    reports: list[UrlReputation],
    *,
    client: httpx.AsyncClient,
    wait_s: float | None = None,
) -> tuple[list[SandboxReport], int, str]:
    started = time.perf_counter()
    settings = get_settings()
    if not settings.enable_sandbox:
        return [], 0, "skipped"
    hashes = _unique_hashes(
        [*_attachment_hashes(email), *[item for report in reports for item in report.downloaded_sha256]],
        settings.sandbox_max_files,
    )
    deadline = time.perf_counter() + max(0.0, settings.sandbox_wait_seconds if wait_s is None else wait_s)
    if not hashes and reports and deadline > time.perf_counter():
        hashes = await _wait_for_downloads(reports, client=client, deadline=deadline, cap=settings.sandbox_max_files)
    if not hashes:
        return [], _elapsed_ms(started), "none"
    found = await asyncio.gather(*[_get_behaviour(item, client=client) for item in hashes])
    out = [item for item in found if item is not None]
    if out and all(item.status == "none" for item in out) and deadline > time.perf_counter():
        await asyncio.sleep(min(2.0, max(0.0, deadline - time.perf_counter())))
        found = await asyncio.gather(*[_get_behaviour(item, client=client) for item in hashes])
        out = [item for item in found if item is not None]
    if any(item.status == "complete" for item in out):
        status = "complete"
    elif any(item.status == "forbidden" for item in out):
        status = "forbidden"
    elif any(item.status == "error" for item in out):
        status = "error"
    else:
        status = "none"
    return out, _elapsed_ms(started), status


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


async def _get_url_report(bare_url: str, *, client: httpx.AsyncClient) -> UrlReputation | None:
    settings = get_settings()
    try:
        response = await client.get(
            VT_URLS + vt_url_id(bare_url),
            headers={"x-apikey": settings.virustotal_api_key},
            params={"relationships": "downloaded_files"},
            timeout=3.0,
            follow_redirects=True,
        )
    except Exception as exc:
        logger.info("VirusTotal URL report failed: %s", type(exc).__name__)
        return None
    if response.status_code == 404:
        return None
    if response.status_code >= 400:
        logger.info("VirusTotal URL report HTTP %s", response.status_code)
        return None
    try:
        payload = response.json()
    except Exception:
        return None
    return _reputation_from_url_doc(bare_url, payload if isinstance(payload, dict) else {})


def _reputation_from_url_doc(bare_url: str, payload: dict) -> UrlReputation | None:
    attrs = (payload.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    if not isinstance(stats, dict) or not stats:
        return None
    results = attrs.get("last_analysis_results") or attrs.get("results") or {}
    return UrlReputation(
        bare_url=bare_url,
        host=host_of(bare_url),
        status="completed",
        malicious=_stat(stats, "malicious"),
        suspicious=_stat(stats, "suspicious"),
        harmless=_stat(stats, "harmless"),
        undetected=_stat(stats, "undetected"),
        comment=_first_engine_result(results),
        downloaded_sha256=_downloaded_hashes(payload),
    )


def _reputation_from_analysis(bare_url: str, payload: dict) -> UrlReputation:
    attrs = (payload.get("data") or {}).get("attributes") or {}
    stats = attrs.get("stats") or {}
    results = attrs.get("results") or {}
    return UrlReputation(
        bare_url=bare_url,
        host=host_of(bare_url),
        status="completed",
        malicious=_stat(stats, "malicious"),
        suspicious=_stat(stats, "suspicious"),
        harmless=_stat(stats, "harmless"),
        undetected=_stat(stats, "undetected"),
        comment=_first_engine_result(results),
    )


async def _submit_one(bare_url: str, *, client: httpx.AsyncClient) -> str:
    settings = get_settings()
    response = await client.post(
        VT_SUBMIT,
        headers={"x-apikey": settings.virustotal_api_key, "content-type": "application/x-www-form-urlencoded"},
        data={"url": bare_url},
        timeout=4.0,
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
        timeout=3.0,
        follow_redirects=True,
    )
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


def _stat(stats: dict, key: str) -> int:
    try:
        return max(0, int(stats.get(key) or 0))
    except (TypeError, ValueError):
        return 0


def _attachment_hashes(email: EmailInput) -> list[str]:
    from app.layers import file_inspect

    return [report.sha256 for report in file_inspect.inspect_attachments(email.attachments).reports if report.sha256]


def _unique_hashes(values: list[str], cap: int) -> list[str]:
    seen: list[str] = []
    for item in values:
        digest = (item or "").strip().lower()
        if len(digest) != 64 or digest in seen:
            continue
        seen.append(digest)
        if cap > 0 and len(seen) >= cap:
            break
    return seen


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.perf_counter() - started) * 1000))


async def _wait_for_downloads(
    reports: list[UrlReputation],
    *,
    client: httpx.AsyncClient,
    deadline: float,
    cap: int,
) -> list[str]:
    hashes: list[str] = []
    while time.perf_counter() < deadline and not hashes:
        await asyncio.sleep(min(2.0, max(0.2, deadline - time.perf_counter())))
        fresh = await lookup_url_reports([item.bare_url for item in reports], client=client)
        hashes = _unique_hashes([item for report in fresh for item in report.downloaded_sha256], cap)
    return hashes


def _downloaded_hashes(payload: dict) -> tuple[str, ...]:
    rel = ((payload.get("data") or {}).get("relationships") or {}).get("downloaded_files") or {}
    rows = rel.get("data") if isinstance(rel, dict) else None
    if not isinstance(rows, list):
        return ()
    out: list[str] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        digest = str(item.get("id") or "").strip().lower()
        if len(digest) == 64 and digest not in out:
            out.append(digest)
        if len(out) >= 5:
            break
    return tuple(out)


async def _get_behaviour(sha256: str, *, client: httpx.AsyncClient) -> SandboxReport | None:
    settings = get_settings()
    try:
        response = await client.get(
            VT_FILES + sha256 + "/behaviour_summary",
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=4.0,
            follow_redirects=True,
        )
    except Exception as exc:
        logger.info("VirusTotal sandbox lookup failed: %s", type(exc).__name__)
        return SandboxReport(sha256=sha256, status="error")
    if response.status_code == 404:
        return SandboxReport(sha256=sha256, status="none")
    if response.status_code in {401, 403}:
        logger.info("VirusTotal sandbox HTTP %s", response.status_code)
        return SandboxReport(sha256=sha256, status="forbidden")
    if response.status_code >= 400:
        logger.info("VirusTotal sandbox HTTP %s", response.status_code)
        return SandboxReport(sha256=sha256, status="error")
    try:
        payload = response.json()
    except Exception:
        return SandboxReport(sha256=sha256, status="error")
    data = payload.get("data") if isinstance(payload, dict) else None
    attrs = data if isinstance(data, dict) else {}
    if "attributes" in attrs and isinstance(attrs.get("attributes"), dict):
        attrs = attrs["attributes"]
    tags = _string_tuple(attrs.get("tags"), 8)
    verdicts = _verdicts(attrs)
    comment = sanitize_vendor_text(" ".join([*verdicts, *tags]))
    return SandboxReport(
        sha256=sha256,
        status="complete",
        malicious=_sandbox_malicious(tags, verdicts, attrs),
        tags=tags,
        verdicts=verdicts,
        dns_lookups=_count_field(attrs, "dns_lookups"),
        files_dropped=_count_field(attrs, "files_dropped") or _count_field(attrs, "files_written"),
        comment=comment,
    )


def _string_tuple(value: object, cap: int) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    out: list[str] = []
    for item in value:
        text = sanitize_vendor_text(str(item or ""))
        if text and text not in out:
            out.append(text[:40])
        if len(out) >= cap:
            break
    return tuple(out)


def _verdicts(attrs: dict) -> tuple[str, ...]:
    raw = attrs.get("verdicts") or attrs.get("verdict")
    if isinstance(raw, dict):
        collected: list[str] = []
        for key in ("malicious", "harmless", "benign", "suspicious"):
            collected.extend(_string_tuple(raw.get(key), 4))
        return tuple(collected[:8])
    return _string_tuple(raw, 6)


def _sandbox_malicious(tags: tuple[str, ...], verdicts: tuple[str, ...], attrs: dict) -> bool:
    lowered = {item.lower() for item in [*tags, *verdicts]}
    if lowered & SANDBOX_MALICIOUS_TAGS:
        return True
    severity = str(attrs.get("threat_severity") or attrs.get("severity") or "").lower()
    if severity in {"high", "critical", "malicious"}:
        return True
    matches = attrs.get("signature_matches")
    return isinstance(matches, list) and len(matches) > 0


def _count_field(attrs: dict, key: str) -> int:
    value = attrs.get(key)
    if isinstance(value, list):
        return len(value)
    return _stat(attrs, key) if isinstance(value, (int, str)) else 0


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
