"""Verify Firebase ID tokens without firebase-admin (Google certs via google-auth)."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def verify_firebase_id_token(id_token: str, project_id: str) -> dict:
    """Return decoded claims or raise ValueError."""
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token
    except ImportError as exc:
        raise ValueError(
            "google-auth is not installed. pip install google-auth to enable /v1/account/token."
        ) from exc
    try:
        claims = google_id_token.verify_firebase_token(
            id_token,
            google_requests.Request(),
            audience=project_id,
        )
    except Exception as exc:  # noqa: BLE001 — surface as auth failure
        logger.info("firebase token rejected: %s", type(exc).__name__)
        raise ValueError("Invalid Firebase ID token") from exc
    if not claims or not claims.get("sub"):
        raise ValueError("Invalid Firebase ID token")
    return claims
