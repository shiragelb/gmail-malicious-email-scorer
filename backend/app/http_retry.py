"""Retry transient HTTP failures for threat-intelligence lookups."""

from __future__ import annotations

import asyncio
import logging

import httpx

logger = logging.getLogger(__name__)

_RETRY_EXCEPTIONS = (
    httpx.TimeoutException,
    httpx.NetworkError,
    httpx.RemoteProtocolError,
)


async def request_with_retries(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    retries: int = 2,
    backoff_seconds: float = 0.25,
    **kwargs,
) -> httpx.Response:
    """POST/GET with up to ``retries`` repeats on timeout, network error, or HTTP 5xx."""
    attempt = 0
    while True:
        try:
            response = await client.request(method, url, **kwargs)
            if response.status_code >= 500 and attempt < retries:
                attempt += 1
                logger.info("HTTP %s on %s — retry %s/%s", response.status_code, url, attempt, retries)
                await asyncio.sleep(backoff_seconds * attempt)
                continue
            return response
        except _RETRY_EXCEPTIONS as exc:
            if attempt >= retries:
                raise
            attempt += 1
            logger.info("%s on %s — retry %s/%s", type(exc).__name__, url, attempt, retries)
            await asyncio.sleep(backoff_seconds * attempt)
