"""Stateless per-user API tokens derived from Firebase UID + ACCOUNT_TOKEN_SECRET."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from app.config import Settings

_PREFIX = "mg1."


def mint_user_token(uid: str, secret: str) -> str:
    uid = uid.strip()
    if not uid or not secret:
        raise ValueError("uid and secret required")
    digest = hmac.new(secret.encode("utf-8"), uid.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    return f"{_PREFIX}{uid}.{digest}"


def token_uid_if_valid(token: str, secret: str) -> str | None:
    if not token or not secret or not token.startswith(_PREFIX):
        return None
    body = token[len(_PREFIX) :]
    if "." not in body:
        return None
    uid, digest = body.rsplit(".", 1)
    if not uid or len(digest) != 32:
        return None
    expected = hmac.new(secret.encode("utf-8"), uid.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(digest, expected):
        return None
    return uid


def new_random_api_key() -> str:
    return secrets.token_urlsafe(24)


def firebase_configured(settings: Settings) -> bool:
    return bool(settings.firebase_project_id and settings.account_token_secret)
