"""FastAPI service that scores one email and, in dev mode, serves the local demo page."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import ValidationError

from app.account_tokens import firebase_configured, mint_user_token
from app.auth_keys import auth_configured, key_is_valid
from app.config import get_settings
from app.firebase_auth import verify_firebase_id_token
from app.budget import ledger
from app.layers.deep_scan import (
    BudgetPaused,
    SANDBOX_DISCLAIMER,
    ScanItem,
    UrlReputation,
    canned_sandbox_email,
    collect_sandbox,
    deep_scan_configured,
    extract_bare_urls,
    interpret_reports,
    interpret_sandbox,
    lookup_url_reports,
    mint_scan_token,
    parse_scan_token,
    sandbox_configured,
    submit_urls,
    wait_for_analyses,
)
from app.layers.domain_age import lookups_enabled, whois_available
from app.pipeline import analyze_email
from app.scenarios import SCENARIOS
from app.schemas import AnalysisResponse, DeepScanResultRequest, EmailInput, Finding
from app.security import (
    NonceStore,
    RateLimiter,
    caller_key,
    read_limited_body,
    safe_validation_errors,
    verify_signature,
)

_DEMO = Path(__file__).resolve().parent / "static" / "demo.html"
_TESTS = Path(__file__).resolve().parent / "static" / "tests.html"
_QUIET_LOGGERS = (
    "uvicorn.access",
    "httpx",
    "httpcore",
    "urllib3",
    "transformers",
    "filelock",
    "onnxruntime",
)

_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
_DEMO_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
_DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "frame-ancestors 'none'"
)

nonces = NonceStore()
rate_limiter = RateLimiter()
deep_scan_limiter = RateLimiter()


def configure_logging() -> None:
    level = get_settings().effective_log_level
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s", force=True)
    for name in _QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


configure_logging()


@asynccontextmanager
async def _lifespan(app: FastAPI):
    settings = get_settings()
    problems = settings.startup_problems()
    if problems:
        raise RuntimeError("Refusing to start outside DEV_MODE: " + " ".join(problems))
    configure_logging()
    timeout = httpx.Timeout(4.0, connect=3.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        app.state.http = client
        if settings.use_onnx_classifier:
            from app.layers.onnx_classifier import warmup

            warmup()
        yield


app = FastAPI(
    title="Malicious Email Scorer",
    summary="Scores an opened Gmail message for phishing and malware risk.",
    version="1.1.0",
    lifespan=_lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    path = request.url.path
    if request.method == "OPTIONS" and path == "/v1/demo/sandbox":
        response = Response(status_code=204)
    else:
        response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if path in ("/", "/tests"):
        response.headers.setdefault("Content-Security-Policy", _DEMO_CSP)
    elif path == "/docs":
        response.headers.setdefault("Content-Security-Policy", _DOCS_CSP)
    else:
        response.headers.setdefault("Content-Security-Policy", _API_CSP)
    if path.startswith("/v1/"):
        response.headers["Cache-Control"] = "no-store"
    if path in {"/tests", "/v1/demo/sandbox"}:
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "X-API-Key, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.exception_handler(RequestValidationError)
async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    del request
    return JSONResponse(status_code=422, content={"detail": safe_validation_errors(list(exc.errors()))})


def _require_dev() -> None:
    if not get_settings().dev_mode:
        raise HTTPException(status_code=404, detail="Not Found")


def _authorize(provided: str | None) -> None:
    settings = get_settings()
    if not auth_configured(settings):
        return
    if not key_is_valid(provided, settings):
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/health")
def health() -> dict:
    settings = get_settings()
    if not settings.dev_mode:
        return {"status": "ok"}
    return {
        "status": "ok",
        "auth_required": auth_configured(settings),
        "signing_required": bool(settings.request_signing_secret),
        "account_tokens": firebase_configured(settings),
        "llm_mode": settings.llm_mode,
        "providers": {
            "urlhaus": bool(settings.urlhaus_auth_key),
            "phishtank": bool(settings.phishtank_api_key),
            "safe_browsing": bool(settings.safe_browsing_api_key),
            "anthropic": bool(settings.anthropic_api_key),
            "virustotal": bool(settings.virustotal_api_key),
            "whois": whois_available(),
            "domain_age": lookups_enabled(),
            "live_dns": settings.enable_live_dns,
            "transformers": settings.use_transformers,
            "onnx": settings.use_onnx_classifier,
            "huggingface": bool(settings.use_hf_classifier and settings.hf_token),
            "deep_scan": deep_scan_configured(),
            "sandbox": sandbox_configured(),
        },
        "budget": ledger().snapshot(),
    }


@app.get("/v1/demo/scenarios")
def demo_scenarios() -> list[dict]:
    _require_dev()
    return [scenario.model_dump() for scenario in SCENARIOS]


@app.post("/v1/demo/sandbox")
async def demo_sandbox(
    request: Request,
    x_api_key: str | None = Header(default=None),
) -> dict:
    """Canned VirusTotal sandbox lookup for the hard-tests page. Not used by the Gmail scorer."""
    _authorize(x_api_key)
    if not rate_limiter.allow(caller_key(x_api_key, request), per_minute=get_settings().rate_limit_per_minute):
        raise HTTPException(status_code=429, detail="Too many requests", headers={"Retry-After": "10"})
    if not sandbox_configured():
        raise HTTPException(status_code=503, detail="Sandbox is not configured on this server.")
    if ledger().optional_paused:
        raise HTTPException(status_code=503, detail="Optional scans are paused for the daily budget.")
    http = getattr(request.app.state, "http", None)
    if http is None:
        raise HTTPException(status_code=503, detail="Sandbox client is not ready.")
    started = time.perf_counter()
    reports, _sandbox_ms, status = await collect_sandbox(canned_sandbox_email(), [], client=http)
    matches, _notes, evidence = interpret_sandbox(reports)
    del _sandbox_ms, _notes
    return {
        "status": status or "none",
        "elapsed_ms": max(0, int((time.perf_counter() - started) * 1000)),
        "malicious": any(match.confirmed for match in matches),
        "files": evidence.get("files") or [],
        "disclaimer": SANDBOX_DISCLAIMER,
    }


@app.post("/v1/account/token")
def mint_account_token(authorization: str | None = Header(default=None)) -> dict:
    """Exchange a Firebase ID token for a stable per-user API key (no database)."""
    settings = get_settings()
    if not firebase_configured(settings):
        raise HTTPException(status_code=404, detail="Not Found")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer Firebase ID token required")
    raw = authorization.split(" ", 1)[1].strip()
    try:
        claims = verify_firebase_id_token(raw, settings.firebase_project_id)
        token = mint_user_token(str(claims["sub"]), settings.account_token_secret)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return {
        "api_key": token,
        "email": claims.get("email"),
        "uid": claims.get("sub"),
    }


@app.post(
    "/v1/analyze",
    response_model=AnalysisResponse,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": EmailInput.model_json_schema()}},
        }
    },
)
async def analyze(
    request: Request,
    x_api_key: str | None = Header(default=None),
    x_timestamp: str | None = Header(default=None),
    x_nonce: str | None = Header(default=None),
    x_signature: str | None = Header(default=None),
) -> AnalysisResponse | JSONResponse:
    settings = get_settings()
    _authorize(x_api_key)
    if not rate_limiter.allow(caller_key(x_api_key, request), per_minute=settings.rate_limit_per_minute):
        raise HTTPException(status_code=429, detail="Too many requests", headers={"Retry-After": "10"})
    raw = await read_limited_body(request, settings.max_request_bytes)
    if settings.request_signing_secret:
        verify_signature(
            secret=settings.request_signing_secret,
            body=raw,
            timestamp=x_timestamp,
            nonce=x_nonce,
            signature=x_signature,
            nonces=nonces,
            max_age=settings.signature_max_age_seconds,
        )
    try:
        email = EmailInput.model_validate_json(raw)
    except ValidationError as exc:
        return JSONResponse(status_code=422, content={"detail": safe_validation_errors(exc.errors())})
    http = getattr(request.app.state, "http", None)
    return await analyze_email(email, client=http)


@app.post("/v1/deep-scan", response_model=AnalysisResponse)
async def deep_scan(
    request: Request,
    x_api_key: str | None = Header(default=None),
    x_timestamp: str | None = Header(default=None),
    x_nonce: str | None = Header(default=None),
    x_signature: str | None = Header(default=None),
) -> AnalysisResponse | JSONResponse:
    settings = get_settings()
    parsed = await _authorized_json(
        request,
        x_api_key=x_api_key,
        x_timestamp=x_timestamp,
        x_nonce=x_nonce,
        x_signature=x_signature,
        model=EmailInput,
    )
    if isinstance(parsed, JSONResponse):
        return parsed
    email, http = parsed
    caller = caller_key(x_api_key, request)
    if not deep_scan_limiter.allow_per_hour(caller, per_hour=settings.deep_scan_per_hour):
        raise HTTPException(status_code=429, detail="Too many on-demand scans", headers={"Retry-After": "60"})
    return await _start_deep_scan(email, client=http)


@app.post("/v1/deep-scan/result", response_model=AnalysisResponse)
async def deep_scan_result(
    request: Request,
    x_api_key: str | None = Header(default=None),
    x_timestamp: str | None = Header(default=None),
    x_nonce: str | None = Header(default=None),
    x_signature: str | None = Header(default=None),
) -> AnalysisResponse | JSONResponse:
    parsed = await _authorized_json(
        request,
        x_api_key=x_api_key,
        x_timestamp=x_timestamp,
        x_nonce=x_nonce,
        x_signature=x_signature,
        model=DeepScanResultRequest,
    )
    if isinstance(parsed, JSONResponse):
        return parsed
    payload, http = parsed
    return await _finish_deep_scan(payload.scan_id, payload.email, client=http)


async def _authorized_json(
    request: Request,
    *,
    x_api_key: str | None,
    x_timestamp: str | None,
    x_nonce: str | None,
    x_signature: str | None,
    model,
):
    settings = get_settings()
    _authorize(x_api_key)
    if not rate_limiter.allow(caller_key(x_api_key, request), per_minute=settings.rate_limit_per_minute):
        raise HTTPException(status_code=429, detail="Too many requests", headers={"Retry-After": "10"})
    raw = await read_limited_body(request, settings.max_request_bytes)
    if settings.request_signing_secret:
        verify_signature(
            secret=settings.request_signing_secret,
            body=raw,
            timestamp=x_timestamp,
            nonce=x_nonce,
            signature=x_signature,
            nonces=nonces,
            max_age=settings.signature_max_age_seconds,
        )
    try:
        parsed = model.model_validate_json(raw)
    except ValidationError as exc:
        return JSONResponse(status_code=422, content={"detail": safe_validation_errors(exc.errors())})
    http = getattr(request.app.state, "http", None)
    return parsed, http


async def _start_deep_scan(email: EmailInput, *, client: httpx.AsyncClient | None) -> AnalysisResponse:
    started = time.perf_counter()
    urls = extract_bare_urls(email)
    if not deep_scan_configured() or not urls or client is None:
        result = await analyze_email(email, client=client, skip_llm=True)
        result.deep_scan.available = False
        result.deep_scan.recommended = False
        return result
    if ledger().optional_paused:
        return _mark_paused(await analyze_email(email, client=client, skip_llm=True))
    try:
        cached = await lookup_url_reports(urls, client=client)
        missing = [url for url in urls if url not in {item.bare_url for item in cached}]
        items = await submit_urls(missing, client=client) if missing else []
    except BudgetPaused:
        return _mark_paused(await analyze_email(email, client=client, skip_llm=True))
    except Exception:
        result = await analyze_email(email, client=client, skip_llm=True)
        result.deep_scan.status = "error"
        result.deep_scan.available = True
        return result
    reports = list(cached)
    if items:
        try:
            status, fresh = await wait_for_analyses(_token_items(items), urls, client=client, attempts=2, delay_s=0.3)
        except Exception:
            status, fresh = "error", []
        reports = _merge_reports(reports, fresh)
        if status == "error" and not reports:
            result = await analyze_email(email, client=client, skip_llm=True)
            result.deep_scan.status = "error"
            result.deep_scan.available = True
            return result
        still = [url for url in urls if url not in {item.bare_url for item in reports}]
        if still:
            reports = _merge_reports(reports, await lookup_url_reports(still, client=client))
    if reports:
        return await _apply_reputation(
            email,
            reports,
            client=client,
            scan_id=mint_scan_token(items) if items else "",
            started=started,
        )
    return await _settle_unconfirmed(email, client=client, started=started)


async def _finish_deep_scan(
    scan_id: str,
    email: EmailInput,
    *,
    client: httpx.AsyncClient | None,
) -> AnalysisResponse:
    started = time.perf_counter()
    try:
        token_items = parse_scan_token(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid or expired scan token") from None
    urls = extract_bare_urls(email)
    if client is None:
        return await _settle_unconfirmed(email, client=None, started=started)
    try:
        status, reports = await wait_for_analyses(token_items, urls, client=client, attempts=1, delay_s=0.3)
    except Exception:
        result = await analyze_email(email, client=None)
        result.deep_scan.status = "error"
        result.deep_scan.scan_id = scan_id
        result.deep_scan.available = True
        return result
    if status != "completed":
        reports = _merge_reports(reports, await lookup_url_reports(urls, client=client))
    if reports:
        return await _apply_reputation(email, reports, client=client, scan_id=scan_id, started=started)
    if status == "error":
        result = await analyze_email(email, client=None)
        result.deep_scan.status = "error"
        result.deep_scan.scan_id = scan_id
        result.deep_scan.available = True
        return result
    return await _settle_unconfirmed(email, client=client, started=started)


async def _apply_reputation(
    email: EmailInput,
    reports,
    *,
    client: httpx.AsyncClient | None,
    scan_id: str,
    started: float | None = None,
) -> AnalysisResponse:
    matches, notes, evidence = interpret_reports(reports)
    applied = "confirmed" if any(match.confirmed for match in matches) else "note"
    result = await analyze_email(
        email,
        client=client,
        extra_url_matches=matches,
        extra_findings=notes,
        sandbox_evidence=evidence,
        reputation_applied=applied,
        skip_llm=True,
    )
    result.deep_scan.status = "complete"
    result.deep_scan.scan_id = scan_id
    result.deep_scan.available = False
    result.deep_scan.recommended = False
    result.deep_scan.paused = False
    if started is not None:
        result.deep_scan.elapsed_ms = max(0, int((time.perf_counter() - started) * 1000))
    return result


async def _settle_unconfirmed(
    email: EmailInput,
    *,
    client: httpx.AsyncClient | None,
    started: float | None = None,
) -> AnalysisResponse:
    result = await analyze_email(
        email,
        client=client,
        extra_findings=[
            Finding(
                layer="url",
                code="deep_scan_note",
                polarity="note",
                text="On-demand scanners did not finish in time. The local score still stands.",
                points=0,
            )
        ],
        reputation_applied="timeout",
        skip_llm=True,
    )
    result.deep_scan.status = "complete"
    result.deep_scan.scan_id = ""
    result.deep_scan.available = False
    result.deep_scan.recommended = False
    result.deep_scan.paused = False
    if started is not None:
        result.deep_scan.elapsed_ms = max(0, int((time.perf_counter() - started) * 1000))
    return result


def _token_items(items: list[ScanItem]) -> list[dict]:
    return [{"h": item.url_hash, "a": item.analysis_id} for item in items]


def _merge_reports(*groups: list[UrlReputation]) -> list[UrlReputation]:
    by_url: dict[str, UrlReputation] = {}
    for group in groups:
        for report in group:
            by_url[report.bare_url] = report
    return list(by_url.values())


def _mark_paused(result: AnalysisResponse) -> AnalysisResponse:
    result.deep_scan.available = False
    result.deep_scan.recommended = False
    result.deep_scan.paused = True
    result.deep_scan.status = "paused"
    result.deep_scan.scan_id = ""
    return result


@app.get("/")
def demo_page() -> FileResponse:
    _require_dev()
    return FileResponse(_DEMO)


@app.get("/tests")
def tests_page() -> FileResponse:
    return FileResponse(_TESTS)


@app.get("/openapi.json", include_in_schema=False)
def openapi_schema() -> dict:
    _require_dev()
    return app.openapi()


@app.get("/docs", include_in_schema=False)
def docs_page():
    _require_dev()
    return get_swagger_ui_html(openapi_url="/openapi.json", title="Malicious Email Scorer")
