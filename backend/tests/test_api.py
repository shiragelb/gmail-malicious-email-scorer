"""API contract: health, scenario scoring, auth, and a feed outage."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["providers"]["urlhaus"] is False
    assert body["providers"]["anthropic"] is False


def test_analyze_classic_phishing_scenario(client):
    from app.scenarios import scenario_by_id

    scenario = scenario_by_id("B")
    response = client.post("/v1/analyze", json=scenario.email.model_dump())
    assert response.status_code == 200
    body = response.json()
    assert 85 <= body["score"] <= 100
    assert body["verdict"] == "Malicious"
    assert body["color"] == "red"
    assert "report_phishing" in body["suggested_actions"]


def test_missing_api_key_is_rejected(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "local-test-key")
    get_settings.cache_clear()
    from app.auth_keys import clear_key_caches

    clear_key_caches()
    response = client.post("/v1/analyze", json={"from_address": "a@example.com", "subject": "Hi", "body_text": "Hello"})
    assert response.status_code == 401
    allowed = client.post(
        "/v1/analyze",
        headers={"X-API-Key": "local-test-key"},
        json={"from_address": "a@example.com", "subject": "Hi", "body_text": "Hello"},
    )
    assert allowed.status_code == 200


def test_extra_api_keys_are_accepted(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "shared-master-key-xxxx")
    monkeypatch.setenv("API_KEYS", "user-token-aaaaaaaa,user-token-bbbbbbbb")
    get_settings.cache_clear()
    from app.auth_keys import clear_key_caches

    clear_key_caches()
    denied = client.post("/v1/analyze", json={"from_address": "a@example.com", "subject": "Hi", "body_text": "Hello"})
    assert denied.status_code == 401
    for key in ("shared-master-key-xxxx", "user-token-aaaaaaaa", "user-token-bbbbbbbb"):
        ok = client.post(
            "/v1/analyze",
            headers={"X-API-Key": key},
            json={"from_address": "a@example.com", "subject": "Hi", "body_text": "Hello"},
        )
        assert ok.status_code == 200, key


def test_threat_feed_exception_still_returns_a_score(client, monkeypatch):
    async def broken(urls, **kwargs):
        del urls, kwargs
        raise TimeoutError("feed timed out")

    monkeypatch.setattr("app.layers.url_intel.screen_urls", broken)
    response = client.post(
        "/v1/analyze",
        json={
            "from_display": "Jordan Lee",
            "from_address": "jordan.lee@gmail.com",
            "subject": "Hello",
            "body_text": "Thursday still works.",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert 0 <= body["score"] <= 100
    assert any("timed out" in reason["text"] or "error" in reason["text"].lower() for reason in body["reasons"])
