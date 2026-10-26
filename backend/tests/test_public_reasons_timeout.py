"""Feed outage findings stay off the public sidebar list."""

from __future__ import annotations

from app.schemas import Finding
from app.scoring import public_reasons


def test_intel_timeout_notes_are_hidden_from_sidebar():
    reasons = public_reasons(
        [
            Finding(
                layer="url",
                code="intel_unavailable",
                polarity="note",
                text="A threat-intelligence feed timed out or returned an error.",
                points=0,
            ),
            Finding(
                layer="attachment",
                code="hash_intel_unavailable",
                polarity="note",
                text="MalwareBazaar timed out or returned an error.",
                points=0,
            ),
            Finding(
                layer="authentication",
                code="auth_pass",
                polarity="trust",
                text="SPF, DKIM, and DMARC all passed.",
                points=-8,
            ),
        ]
    )
    texts = " ".join(item.text.lower() for item in reasons)
    assert "timed out" not in texts
    assert any("came from" in item.text.lower() for item in reasons)
