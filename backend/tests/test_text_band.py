"""Severe scam wording reaches Suspicious. Ordinary password-reset mail stays Safe."""

from __future__ import annotations

import pytest

from app.pipeline import analyze_email
from app.schemas import EmailInput
from app.scoring import ScoreDecision, apply_guardrails

_PASSWORD_RESET = (
    "Hi, please reset your password here: https://acme-widgets.test/account/reset "
    "If you did not request this, you can ignore the message."
)

_URGENCY = (
    "Your account has been suspended. Verify your password immediately "
    "or access will be removed. Details are at https://acme-widgets.test/help"
)

_ADVANCE_FEE = (
    "Dear grandchild, I am your grandmother Helene. I am old and far away. "
    "I will send you $10,000,000 if you help me build farms in Alaska. "
    "Reply with your bank details so I can transfer the funds."
)


@pytest.mark.asyncio
async def test_password_reset_from_a_small_company_stays_safe():
    result = await analyze_email(
        EmailInput(
            subject="Reset your password",
            from_display="Acme Widgets",
            from_address="help@acme-widgets.test",
            body_text=_PASSWORD_RESET,
        )
    )
    assert result.layers["text"]["is_phishing"] is True
    assert result.layers["text"]["is_severe"] is False
    assert result.layers["meta"]["band"] == "credential"
    assert result.verdict == "Safe"
    assert result.score <= 35
    assert "password" in " ".join(reason.text for reason in result.reasons).lower()


@pytest.mark.asyncio
async def test_account_urgency_without_other_signals_stays_safe():
    result = await analyze_email(
        EmailInput(
            subject="Account notice",
            from_display="Ada Lovelace",
            from_address="ada@example.com",
            body_text=_URGENCY,
        )
    )
    assert result.layers["text"]["is_severe"] is False
    assert result.verdict == "Safe"
    assert result.score <= 35
    assert result.verdict != "Malicious"


@pytest.mark.asyncio
async def test_hugging_face_cannot_push_a_password_reset_to_suspicious(monkeypatch):
    monkeypatch.setattr("app.layers.text_classifier._transformer_probability", lambda text: 0.99)
    result = await analyze_email(
        EmailInput(
            subject="Reset your password",
            from_display="Acme Widgets",
            from_address="help@acme-widgets.test",
            body_text=_PASSWORD_RESET,
        )
    )
    assert result.layers["text"]["transformer_probability"] == 0.99
    assert result.layers["text"]["is_severe"] is False
    assert result.verdict == "Safe"
    assert result.score <= 35


@pytest.mark.asyncio
async def test_advance_fee_wording_is_suspicious_but_not_malicious():
    result = await analyze_email(
        EmailInput(
            subject="Family help",
            from_display="Helene",
            from_address="helene@mail.test",
            body_text=_ADVANCE_FEE,
        )
    )
    assert result.layers["text"]["is_severe"] is True
    assert result.layers["meta"]["band"] == "text"
    assert result.verdict == "Suspicious"
    assert 48 <= result.score <= 70
    assert result.verdict != "Malicious"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "subject,body",
    [
        (
            "Your order has shipped",
            "Order 1842 left the warehouse this morning. Tracking is at https://example.com/orders/1842",
        ),
        (
            "October notes",
            "This month's newsletter covers the index rebuild. No action is needed.",
        ),
        (
            "Lunch",
            "Are you free for lunch tomorrow at the cafe downstairs?",
        ),
    ],
)
async def test_benign_text_stays_safe(subject, body):
    result = await analyze_email(
        EmailInput(
            subject=subject,
            from_display="Ada Lovelace",
            from_address="ada@example.com",
            body_text=body,
        )
    )
    assert result.layers["text"]["is_phishing"] is False
    assert result.verdict == "Safe"
    assert result.score <= 15


@pytest.mark.asyncio
async def test_html_href_is_extracted_when_the_text_has_no_url():
    result = await analyze_email(
        EmailInput(
            subject="Notes",
            from_display="Ada Lovelace",
            from_address="ada@example.com",
            body_text="The notes are ready.",
            body_html='<p>The notes are ready.</p><a href="https://example.com/notes">open</a>',
        )
    )
    assert "https://example.com/notes" in result.layers["urls"]["extracted"]
    assert result.verdict == "Safe"


def test_language_model_stays_inside_the_text_band():
    local = ScoreDecision(score=48, verdict="Suspicious", band="text", summary="Wording.")
    assert apply_guardrails(local, 99) == 70
    assert apply_guardrails(local, 5) == 48
    assert apply_guardrails(local, 60) == 60


def test_language_model_cannot_lift_a_password_reset_to_suspicious():
    local = ScoreDecision(score=10, verdict="Safe", band="credential", summary="Password request.")
    assert apply_guardrails(local, 90) == 35
    assert apply_guardrails(local, 4) == 4
