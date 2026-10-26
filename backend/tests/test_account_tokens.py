"""Stateless mg1 user tokens."""

from __future__ import annotations

from app.account_tokens import mint_user_token, token_uid_if_valid
from app.auth_keys import clear_key_caches, key_is_valid
from app.config import get_settings


def test_mint_and_verify_roundtrip():
    secret = "x" * 32
    token = mint_user_token("firebase-uid-123", secret)
    assert token.startswith("mg1.")
    assert token_uid_if_valid(token, secret) == "firebase-uid-123"
    tampered = token[:-1] + ("1" if token[-1] != "1" else "2")
    assert token_uid_if_valid(tampered, secret) is None


def test_key_is_valid_accepts_mg1_tokens(monkeypatch):
    monkeypatch.setenv("API_KEY", "")
    monkeypatch.setenv("API_KEYS", "")
    monkeypatch.setenv("ACCOUNT_TOKEN_SECRET", "account-secret-at-least-32-chars!!")
    get_settings.cache_clear()
    clear_key_caches()
    settings = get_settings()
    token = mint_user_token("uid-abc", settings.account_token_secret)
    assert key_is_valid(token, settings) is True
    assert key_is_valid("mg1.uid-abc.deadbeef", settings) is False
