"""Request authenticity and abuse controls for the public scoring endpoint."""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time

from fastapi import HTTPException, Request

_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_TRACKED_NONCES = 50_000


async def read_limited_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > limit:
                raise HTTPException(status_code=413, detail="Request body too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from None
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            raise HTTPException(status_code=413, detail="Request body too large")
        chunks.append(chunk)
    return b"".join(chunks)


def signing_payload(timestamp: str, nonce: str, body: bytes) -> bytes:
    return f"{timestamp}.{nonce}.{hashlib.sha256(body).hexdigest()}".encode("ascii")


def sign(secret: str, timestamp: str, nonce: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), signing_payload(timestamp, nonce, body), hashlib.sha256).hexdigest()


class NonceStore:
    """Remembers recently used nonces so a captured request cannot be replayed."""

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def claim(self, nonce: str, *, now: float, ttl: float) -> bool:
        with self._lock:
            if len(self._seen) > _MAX_TRACKED_NONCES or len(self._seen) % 256 == 0:
                expired = [key for key, expiry in self._seen.items() if expiry <= now]
                for key in expired:
                    del self._seen[key]
            if len(self._seen) > _MAX_TRACKED_NONCES:
                return False
            expiry = self._seen.get(nonce)
            if expiry is not None and expiry > now:
                return False
            self._seen[nonce] = now + ttl
            return True

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


def verify_signature(
    *,
    secret: str,
    body: bytes,
    timestamp: str | None,
    nonce: str | None,
    signature: str | None,
    nonces: NonceStore,
    max_age: int,
    now: float | None = None,
) -> None:
    rejected = HTTPException(status_code=401, detail="Invalid request signature")
    if not timestamp or not nonce or not signature:
        raise rejected
    if not timestamp.isdigit() or not _NONCE_RE.match(nonce) or not _SIGNATURE_RE.match(signature.lower()):
        raise rejected
    current = time.time() if now is None else now
    if abs(current - int(timestamp)) > max_age:
        raise rejected
    expected = sign(secret, timestamp, nonce, body)
    if not hmac.compare_digest(expected, signature.lower()):
        raise rejected
    # Claim the nonce only after the signature is valid, so forged requests cannot burn nonces.
    if not nonces.claim(nonce, now=current, ttl=2 * max_age):
        raise rejected


class RateLimiter:
    """In-memory token bucket per caller. One instance per process."""

    def __init__(self) -> None:
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, *, per_minute: int, now: float | None = None) -> bool:
        if per_minute <= 0:
            return True
        current = time.monotonic() if now is None else now
        capacity = float(per_minute)
        refill = per_minute / 60.0
        with self._lock:
            tokens, updated = self._buckets.get(key, (capacity, current))
            tokens = min(capacity, tokens + (current - updated) * refill)
            if tokens < 1.0:
                self._buckets[key] = (tokens, current)
                return False
            self._buckets[key] = (tokens - 1.0, current)
            if len(self._buckets) > 10_000:
                self._buckets.clear()
            return True

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()


def caller_key(api_key: str | None, request: Request) -> str:
    if api_key:
        return "key:" + hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
    host = request.client.host if request.client else "unknown"
    return "ip:" + host


def safe_validation_errors(errors: list[dict]) -> list[dict]:
    """Field locations and error types only. Never echo the submitted email content."""
    cleaned = []
    for error in errors[:20]:
        cleaned.append(
            {
                "loc": [str(part)[:80] for part in error.get("loc", ())][:6],
                "type": str(error.get("type", "value_error"))[:60],
                "msg": str(error.get("msg", "Invalid value"))[:200],
            }
        )
    return cleaned
