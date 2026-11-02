"""Time VirusTotal sandbox lookups. Never prints the API key."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.config import get_settings  # noqa: E402
from app.layers.deep_scan import (  # noqa: E402
    VT_ANALYSIS,
    VT_FILES,
    VT_SUBMIT,
    VT_URLS,
    collect_sandbox,
    interpret_sandbox,
    lookup_url_reports,
    vt_url_id,
)
from app.schemas import AttachmentInput, EmailInput  # noqa: E402

# Standard antivirus test string (not a real virus) and a VirusTotal-documented sample hash.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = hashlib.sha256(EICAR).hexdigest()
DOCUMENTED_SAMPLE = "d529b406724e4db3defbaf15fcd216e66b9c999831e0b1f0c82899f7f8ef6ee1"
BENIGN_URL = "https://example.com/"


async def _get_behaviour(client: httpx.AsyncClient, api_key: str, sha256: str) -> dict:
    started = time.perf_counter()
    response = await client.get(
        VT_FILES + sha256 + "/behaviour_summary",
        headers={"x-apikey": api_key},
        timeout=8.0,
        follow_redirects=True,
    )
    elapsed = round((time.perf_counter() - started) * 1000)
    payload = {}
    try:
        payload = response.json()
    except Exception:
        payload = {}
    data = payload.get("data") if isinstance(payload, dict) else {}
    attrs = data if isinstance(data, dict) else {}
    if isinstance(attrs.get("attributes"), dict):
        attrs = attrs["attributes"]
    tags = attrs.get("tags") if isinstance(attrs, dict) else None
    return {
        "http": response.status_code,
        "ms": elapsed,
        "has_report": response.status_code == 200,
        "tag_count": len(tags) if isinstance(tags, list) else 0,
    }


async def _poll_url_analysis(client: httpx.AsyncClient, api_key: str, timeout_s: float) -> dict:
    started = time.perf_counter()
    submit = await client.post(
        VT_SUBMIT,
        headers={"x-apikey": api_key, "content-type": "application/x-www-form-urlencoded"},
        data={"url": BENIGN_URL},
        timeout=8.0,
    )
    submit_ms = round((time.perf_counter() - started) * 1000)
    analysis_id = ""
    try:
        analysis_id = str(((submit.json().get("data") or {}).get("id") or "")).strip()
    except Exception:
        analysis_id = ""
    status = "submit_http_" + str(submit.status_code)
    polls = 0
    while analysis_id and (time.perf_counter() - started) < timeout_s:
        polls += 1
        poll = await client.get(
            VT_ANALYSIS + analysis_id,
            headers={"x-apikey": api_key},
            timeout=8.0,
            follow_redirects=True,
        )
        try:
            status = str(((poll.json().get("data") or {}).get("attributes") or {}).get("status") or poll.status_code)
        except Exception:
            status = "poll_http_" + str(poll.status_code)
        if str(status).lower() == "completed":
            break
        await asyncio.sleep(2.0)
    url_doc = await client.get(
        VT_URLS + vt_url_id(BENIGN_URL),
        headers={"x-apikey": api_key},
        params={"relationships": "downloaded_files"},
        timeout=8.0,
        follow_redirects=True,
    )
    downloads = 0
    try:
        rows = (((url_doc.json().get("data") or {}).get("relationships") or {}).get("downloaded_files") or {}).get("data")
        downloads = len(rows) if isinstance(rows, list) else 0
    except Exception:
        downloads = 0
    return {
        "submit_http": submit.status_code,
        "submit_ms": submit_ms,
        "polls": polls,
        "status": status,
        "ms": round((time.perf_counter() - started) * 1000),
        "downloaded_files": downloads,
        "url_http": url_doc.status_code,
    }


async def main() -> int:
    get_settings.cache_clear()
    settings = get_settings()
    if not settings.virustotal_api_key:
        print(json.dumps({"ok": False, "reason": "VIRUSTOTAL_API_KEY is not set"}))
        return 1
    timeout = httpx.Timeout(10.0, connect=5.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        eicar = await _get_behaviour(client, settings.virustotal_api_key, EICAR_SHA256)
        sample = await _get_behaviour(client, settings.virustotal_api_key, DOCUMENTED_SAMPLE)
        crawl = await _poll_url_analysis(client, settings.virustotal_api_key, timeout_s=45)
        email = EmailInput(
            subject="Sandbox timing",
            from_address="jordan.lee@gmail.com",
            body_text="See https://example.com/notes",
            attachments=[
                AttachmentInput(
                    name="eicar.com",
                    content_type="application/octet-stream",
                    content_b64=__import__("base64").b64encode(EICAR).decode("ascii"),
                )
            ],
        )
        reports = await lookup_url_reports(["https://example.com/"], client=client)
        sandbox_started = time.perf_counter()
        sandbox_reports, sandbox_ms, sandbox_status = await collect_sandbox(
            email, reports, client=client, wait_s=0
        )
        _matches, _notes, evidence = interpret_sandbox(sandbox_reports)
        del _matches, _notes
        pipeline_ms = round((time.perf_counter() - sandbox_started) * 1000)
    print(
        json.dumps(
            {
                "ok": True,
                "eicar_sha256_prefix": EICAR_SHA256[:12],
                "eicar_behaviour": eicar,
                "documented_sample_behaviour": sample,
                "url_crawl": crawl,
                "collect_sandbox": {
                    "status": sandbox_status,
                    "reported_ms": sandbox_ms,
                    "wall_ms": pipeline_ms,
                    "file_count": len(evidence.get("files") or []),
                },
                "note": (
                    "behaviour_summary is a stored sandbox report lookup, not a new detonation. "
                    "A fresh file detonation on VirusTotal is usually 2–5+ minutes."
                ),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
