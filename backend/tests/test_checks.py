"""Sidebar checklist covers sender, links, files, and pictures."""

from __future__ import annotations

import pytest

from app.pipeline import analyze_email
from app.schemas import AttachmentInput, EmailInput
from app.scoring import SignalFlags, build_checks
from app.scenarios import SCENARIOS


def test_build_checks_for_clean_mail_with_a_link():
    checks = build_checks(
        SignalFlags(auth_passed=True),
        url_count=2,
        url_flagged=0,
        attachment_names=["logo.png", "invoice.pdf"],
        attachment_reports=[
            {
                "name": "invoice.pdf",
                "detected_type": "pdf",
                "sha256": "abc",
                "active": False,
                "malwarebazaar": {"matched": False},
            }
        ],
    )
    by_id = {item.id: item for item in checks}
    assert by_id["sender"].status == "pass"
    assert "Confirmed" in by_id["sender"].detail
    assert by_id["links"].status == "pass"
    assert "2 links" in by_id["links"].detail
    assert by_id["files"].status == "pass"
    assert "PDF" in by_id["files"].detail
    assert by_id["pictures"].status == "skip"
    assert "picture" in by_id["pictures"].detail
    assert by_id["wording"].status == "pass"


def test_build_checks_flags_risky_links_and_active_files():
    checks = build_checks(
        SignalFlags(auth_passed=True, lookalike=True, file_active=True),
        url_count=1,
        url_flagged=1,
        attachment_reports=[
            {
                "name": "macro.xlsm",
                "detected_type": "office",
                "sha256": "def",
                "active": True,
                "malwarebazaar": {"matched": False},
            }
        ],
    )
    by_id = {item.id: item for item in checks}
    assert by_id["links"].status == "warn"
    assert by_id["files"].status == "warn"
    assert "active" in by_id["files"].detail.lower()


@pytest.mark.asyncio
async def test_analyze_returns_checks_for_safe_scenario():
    result = await analyze_email(SCENARIOS[0].email)
    assert result.verdict == "Safe"
    assert result.checks
    ids = [item.id for item in result.checks]
    assert ids == ["sender", "links", "files", "pictures", "wording"]
    assert result.checks[0].status == "pass"
    assert "spf" not in result.checks[0].detail.lower()


@pytest.mark.asyncio
async def test_analyze_reports_pdf_when_present():
    result = await analyze_email(
        EmailInput(
            subject="Invoice",
            from_display="Billing",
            from_address="billing@example.com",
            body_text="Please see the attached invoice.",
            headers=SCENARIOS[0].email.headers,
            attachments=[
                AttachmentInput(
                    name="invoice.pdf",
                    content_type="application/pdf",
                    content_b64=(
                        "JVBERi0xLjQKJeLjz9MKMSAwIG9iago8PAovVHlwZSAvQ2F0YWxvZwovUGFnZXMgMiAwIFIK"
                        "Pj4KZW5kb2JqCjIgMCBvYmoKPDwKL1R5cGUgL1BhZ2VzCi9LaWRzIFszIDAgUl0KL0NvdW50IDEK"
                        "Pj4KZW5kb2JqCjMgMCBvYmoKPDwKL1R5cGUgL1BhZ2UKL1BhcmVudCAyIDAgUgovTWVkaWFCb3gg"
                        "WzAgMCA2MTIgNzkyXQo+PgplbmRvYmoKeHJlZgowIDQKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAw"
                        "MDAwMDE1IDAwMDAwIG4gCjAwMDAwMDAwNjQgMDAwMDAgbiAKMDAwMDAwMDEyMSAwMDAwMCBuIAp0"
                        "cmFpbGVyCjw8Ci9TaXplIDQKL1Jvb3QgMSAwIFIKPj4Kc3RhcnR4cmVmCjIwMQolJUVPRg=="
                    ),
                )
            ],
        )
    )
    files = next(item for item in result.checks if item.id == "files")
    assert "PDF" in files.detail
    assert files.status in {"pass", "warn", "fail"}
