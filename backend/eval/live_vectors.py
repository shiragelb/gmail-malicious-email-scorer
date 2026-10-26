"""Score the active feed and header vectors against the running local scorer.

Default pytest stays offline. Run this only when the server on port 8000 is up.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import httpx

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import get_settings
from app.pipeline import analyze_email
from app.schemas import EmailInput, UrlIntelReport
from eval.vectors import BENIGN_URL_CASES, HEADER_CASES, SAFE_BROWSING_CASES

ENDPOINT = "http://127.0.0.1:8000/v1/analyze"
URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
MALWAREBAZAAR_ENDPOINT = "https://mb-api.abuse.ch/api/v1/"
OUT = Path(__file__).resolve().parent / "live_results.json"


def _urlhaus_case(url: str) -> dict:
    return {
        "id": "urlhaus-recent",
        "tier": 2,
        "role": "malicious",
        "expect_verdict": "Malicious",
        "min_score": 90,
        "max_score": 100,
        "provider": "urlhaus",
        "email": {
            "message_id": "urlhaus-recent",
            "subject": "Link to review",
            "from_display": "Ada Lovelace",
            "from_address": "ada@example.com",
            "body_text": f"Please look at {url} when you have a moment.",
            "body_html": "",
            "headers": {
                "Authentication-Results": (
                    "mx.google.com; spf=pass smtp.mailfrom=ada@example.com; "
                    "dkim=pass header.i=@example.com; dmarc=pass header.from=example.com"
                )
            },
            "attachment_names": [],
        },
    }


def _recent_urlhaus_url(client: httpx.Client) -> str:
    settings = get_settings()
    headers = {"User-Agent": "MaliciousEmailScorer/1.0"}
    if settings.urlhaus_auth_key:
        headers["Auth-Key"] = settings.urlhaus_auth_key
    response = client.get(URLHAUS_RECENT, headers=headers, timeout=30)
    response.raise_for_status()
    payload = response.json()
    urls = payload.get("urls") if isinstance(payload, dict) else None
    if not isinstance(urls, list) or not urls:
        raise RuntimeError("URLhaus recent feed returned no URLs")
    online = [item for item in urls if isinstance(item, dict) and item.get("url_status") == "online" and item.get("url")]
    chosen = (online or [item for item in urls if isinstance(item, dict) and item.get("url")])[0]
    return str(chosen["url"])


def _recent_malwarebazaar_hash(client: httpx.Client) -> str:
    """Return one current SHA-256 from MalwareBazaar. Never downloads a sample."""
    settings = get_settings()
    headers = {"User-Agent": "MaliciousEmailScorer/1.0"}
    if settings.urlhaus_auth_key:
        headers["Auth-Key"] = settings.urlhaus_auth_key
    response = client.post(
        MALWAREBAZAAR_ENDPOINT,
        data={"query": "get_recent", "selector": "time"},
        headers=headers,
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or payload.get("query_status") != "ok":
        raise RuntimeError(f"MalwareBazaar recent feed failed: {payload.get('query_status') if isinstance(payload, dict) else 'bad payload'}")
    rows = payload.get("data")
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("MalwareBazaar recent feed returned no hashes")
    for item in rows:
        if not isinstance(item, dict):
            continue
        digest = str(item.get("sha256_hash") or item.get("sha256") or "").strip().lower()
        if len(digest) == 64:
            return digest
    raise RuntimeError("MalwareBazaar recent feed had no SHA-256 values")


def _score_hash_lookup(client: httpx.Client, digest: str) -> dict:
    """Confirm MalwareBazaar recognizes a current hash without downloading a sample."""
    from app.layers.hash_intel import lookup_hashes
    import asyncio

    started = time.perf_counter()

    async def _run():
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0)) as async_client:
            return await lookup_hashes([digest], client=async_client)

    matches, unavailable = asyncio.run(_run())
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    providers = sorted({item.provider for item in matches})
    ok = bool(matches) and "malwarebazaar" in providers
    return {
        "id": "malwarebazaar-recent",
        "tier": 2,
        "role": "malicious",
        "subject": f"sha256:{digest[:12]}…",
        "expect_verdict": "Malicious",
        "verdict": "Malicious" if ok else "Safe",
        "score": 90 if ok else 0,
        "band": "confirmed" if ok else "clean",
        "engine": "hash_lookup",
        "providers": providers,
        "elapsed_ms": elapsed_ms,
        "passed": ok,
        "unavailable": unavailable,
    }


def _score(client: httpx.Client, case: dict) -> dict:
    started = time.perf_counter()
    response = client.post(ENDPOINT, json=case["email"], timeout=90)
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    response.raise_for_status()
    data = response.json()
    matches = ((data.get("layers") or {}).get("urls") or {}).get("matches") or []
    providers = sorted({item.get("provider") for item in matches if item.get("provider")})
    ok = case["min_score"] <= data["score"] <= case["max_score"] and data["verdict"] == case["expect_verdict"]
    if case.get("provider") and case["provider"] not in providers:
        ok = False
    return {
        "id": case["id"],
        "tier": case["tier"],
        "role": case["role"],
        "subject": case["email"]["subject"],
        "expect_verdict": case["expect_verdict"],
        "verdict": data["verdict"],
        "score": data["score"],
        "band": (data.get("layers") or {}).get("meta", {}).get("band"),
        "engine": (data.get("layers") or {}).get("meta", {}).get("engine"),
        "providers": providers,
        "elapsed_ms": elapsed_ms,
        "passed": ok,
    }


async def _local_ms() -> int:
    email = EmailInput.model_validate(BENIGN_URL_CASES[0]["email"])

    async def empty_screen(urls, **kwargs):
        del kwargs
        return UrlIntelReport(checked=list(urls))

    started = time.perf_counter()
    await analyze_email(email, client=None, url_screen=empty_screen)
    return round((time.perf_counter() - started) * 1000)


def _rates(rows: list[dict]) -> dict:
    malicious = [row for row in rows if row["role"] == "malicious"]
    benign = [row for row in rows if row["role"] == "benign"]
    false_negatives = sum(row["verdict"] == "Safe" for row in malicious)
    false_positives = sum(row["verdict"] == "Malicious" for row in benign)
    correct = 0
    for row in rows:
        if row["role"] == "malicious" and row["verdict"] != "Safe":
            correct += 1
        elif row["role"] == "benign" and row["verdict"] != "Malicious":
            correct += 1
    return {
        "n": len(rows),
        "fnr": false_negatives / len(malicious) if malicious else 0.0,
        "fpr": false_positives / len(benign) if benign else 0.0,
        "accuracy": correct / len(rows) if rows else 0.0,
        "passed": sum(row["passed"] for row in rows),
    }


def main() -> None:
    rows: list[dict] = []
    with httpx.Client() as client:
        recent = _recent_urlhaus_url(client)
        cases = [*SAFE_BROWSING_CASES, _urlhaus_case(recent), *BENIGN_URL_CASES, *HEADER_CASES]
        for case in cases:
            row = _score(client, case)
            rows.append(row)
            print(
                f"{row['id']:20} {row['verdict']:11} {row['score']:3} "
                f"{row['elapsed_ms']:5}ms {'ok' if row['passed'] else 'MISS'}",
                flush=True,
            )
        try:
            digest = _recent_malwarebazaar_hash(client)
            row = _score_hash_lookup(client, digest)
        except Exception as exc:
            row = {
                "id": "malwarebazaar-recent",
                "tier": 2,
                "role": "malicious",
                "subject": "hash lookup",
                "expect_verdict": "Malicious",
                "verdict": "Safe",
                "score": 0,
                "band": "clean",
                "engine": "hash_lookup",
                "providers": [],
                "elapsed_ms": 0,
                "passed": False,
                "error": type(exc).__name__,
            }
        rows.append(row)
        print(
            f"{row['id']:20} {row['verdict']:11} {row['score']:3} "
            f"{row['elapsed_ms']:5}ms {'ok' if row['passed'] else 'MISS'}",
            flush=True,
        )
    local_ms = asyncio.run(_local_ms())
    full_times = [row["elapsed_ms"] for row in rows]
    report = {
        "rows": rows,
        "metrics": _rates(rows),
        "latency_ms": {
            "local_pipeline": local_ms,
            "full_path_min": min(full_times),
            "full_path_max": max(full_times),
            "full_path_median": sorted(full_times)[len(full_times) // 2],
        },
    }
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(
        f"fnr={report['metrics']['fnr']:.2f} fpr={report['metrics']['fpr']:.2f} "
        f"accuracy={report['metrics']['accuracy']:.2f} local={local_ms}ms"
    )
    if not all(row["passed"] for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
