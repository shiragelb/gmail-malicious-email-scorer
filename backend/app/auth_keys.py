"""API key acceptance: shared key, extra keys, file keys, and Firebase-minted mg1 tokens."""

from __future__ import annotations

import hmac
from functools import lru_cache
from pathlib import Path

from app.account_tokens import token_uid_if_valid
from app.config import Settings, get_settings


def _split_keys(raw: str) -> frozenset[str]:
    return frozenset(item.strip() for item in raw.split(",") if item.strip())


@lru_cache
def _file_keys(path: str, mtime_ns: int) -> frozenset[str]:
    del mtime_ns
    if not path:
        return frozenset()
    file_path = Path(path)
    if not file_path.is_file():
        return frozenset()
    keys: set[str] = set()
    for line in file_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        keys.add(line.split("#", 1)[0].strip())
    return frozenset(k for k in keys if k)


def accepted_keys(settings: Settings | None = None) -> frozenset[str]:
    settings = settings or get_settings()
    keys = set(_split_keys(settings.api_keys))
    if settings.api_key:
        keys.add(settings.api_key)
    path = (settings.api_keys_file or "").strip()
    if path:
        try:
            mtime = Path(path).stat().st_mtime_ns
        except OSError:
            mtime = 0
        keys.update(_file_keys(path, mtime))
    return frozenset(keys)


def key_is_valid(provided: str | None, settings: Settings | None = None) -> bool:
    if not provided:
        return False
    settings = settings or get_settings()
    for expected in accepted_keys(settings):
        if len(provided) == len(expected) and hmac.compare_digest(provided, expected):
            return True
    if settings.account_token_secret and token_uid_if_valid(provided, settings.account_token_secret):
        return True
    return False


def auth_configured(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    return bool(accepted_keys(settings) or settings.account_token_secret)


def clear_key_caches() -> None:
    _file_keys.cache_clear()
