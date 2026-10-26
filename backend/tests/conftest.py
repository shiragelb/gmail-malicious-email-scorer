"""Keep unit tests offline and give the API a deterministic threat-intel stub."""

from __future__ import annotations

import pytest

from app.config import get_settings
from app.layers.url_intel import reserved_url_matches
from app.schemas import UrlIntelReport


@pytest.fixture(autouse=True)
def offline_environment(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("API_KEY", "")
    monkeypatch.setenv("API_KEYS", "")
    monkeypatch.setenv("API_KEYS_FILE", "")
    monkeypatch.setenv("REQUEST_SIGNING_SECRET", "")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "0")
    monkeypatch.setenv("LLM_MODE", "redacted")
    monkeypatch.setenv("LLM_SKIP_SENDERS", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.setenv("PHISHTANK_API_KEY", "")
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "")
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "")
    monkeypatch.setenv("ENABLE_LIVE_DNS", "false")
    monkeypatch.setenv("ENABLE_WHOIS", "false")
    monkeypatch.setenv("USE_TRANSFORMERS", "false")
    get_settings.cache_clear()
    from app.auth_keys import clear_key_caches

    clear_key_caches()

    async def _screen(urls, **kwargs):
        del kwargs
        return UrlIntelReport(matches=reserved_url_matches(urls), checked=list(urls))

    monkeypatch.setattr("app.layers.url_intel.screen_urls", _screen)
    from app.main import nonces, rate_limiter

    nonces.clear()
    rate_limiter.clear()
    yield
    clear_key_caches()
    get_settings.cache_clear()
