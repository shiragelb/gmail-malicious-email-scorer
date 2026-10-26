"""Active test vectors from the testing plan.

Header fixtures are safe to score offline. Live feed URLs are added by the runner.
"""

from __future__ import annotations

from app.schemas import EmailInput

_PASS = (
    "mx.google.com; spf=pass smtp.mailfrom={address}; "
    "dkim=pass header.i=@{domain}; dmarc=pass header.from={domain}"
)


def _pass_headers(address: str) -> dict[str, str]:
    domain = address.split("@", 1)[1]
    return {"Authentication-Results": _PASS.format(address=address, domain=domain)}


def _message(
    *,
    message_id: str,
    subject: str,
    display: str,
    address: str,
    body: str,
    headers: dict[str, str] | None = None,
    html: str = "",
) -> dict:
    email = EmailInput(
        message_id=message_id,
        subject=subject,
        from_display=display,
        from_address=address,
        body_text=body,
        body_html=html,
        headers=headers or {},
    )
    return email.model_dump()


HEADER_CASES: list[dict] = [
    {
        "id": "headers-pass",
        "tier": 3,
        "role": "benign",
        "expect_verdict": "Safe",
        "min_score": 0,
        "max_score": 15,
        "gmail_note": "Send this to yourself from the staging account. Gmail will add passing authentication.",
        "email": _message(
            message_id="headers-pass",
            subject="Planning notes",
            display="Jordan Lee",
            address="jordan.lee@gmail.com",
            body=(
                "Hi Priya, thanks for sending the notes from yesterday. "
                "Thursday at 2pm still works. The agenda is on https://github.com"
            ),
            headers=_pass_headers("jordan.lee@gmail.com"),
        ),
    },
    {
        "id": "headers-fail",
        "tier": 3,
        "role": "malicious",
        "expect_verdict": "Malicious",
        "min_score": 85,
        "max_score": 100,
        "gmail_note": (
            "Gmail will not keep a forged SPF fail header on a message you compose. "
            "This case is scored through the API. In the sidebar, use the Safe Browsing test link instead."
        ),
        "email": _message(
            message_id="headers-fail",
            subject="Your account will be suspended",
            display="Google Security",
            address="attacker@malicious-domain.ru",
            body=(
                "Google Security alert: your account will be suspended within 24 hours. "
                "Verify your password immediately: https://g00gle-security.com/login"
            ),
            headers={
                "Authentication-Results": (
                    "mx.example.com; spf=fail smtp.mailfrom=malicious-domain.ru; "
                    "dkim=fail header.i=@malicious-domain.ru; dmarc=fail header.from=malicious-domain.ru"
                ),
                "Received-SPF": "fail (malicious-domain.ru does not designate the sending host)",
            },
        ),
    },
    {
        "id": "headers-targeted",
        "tier": 3,
        "role": "malicious",
        "expect_verdict": "Suspicious",
        "min_score": 60,
        "max_score": 80,
        "gmail_note": "Send this to yourself. Passing Gmail authentication plus the lookalike link should stay Suspicious.",
        "email": _message(
            message_id="headers-targeted",
            subject="Quick confirmation on your account access",
            display="Alex Morgan",
            address="alex.morgan@contoso.com",
            body=(
                "Hi Alex, I hope you're doing well. Our identity provider is rotating credentials this week, "
                "and your mailbox is on the list. When you have a moment, could you confirm your password here "
                "so access isn't interrupted: https://contoso-account-secure.com/login Thank you, IT Helpdesk"
            ),
            headers=_pass_headers("alex.morgan@contoso.com"),
        ),
    },
]


SAFE_BROWSING_CASES: list[dict] = [
    {
        "id": "sb-phishing",
        "tier": 2,
        "role": "malicious",
        "expect_verdict": "Malicious",
        "min_score": 90,
        "max_score": 100,
        "provider": "safebrowsing",
        "email": _message(
            message_id="sb-phishing",
            subject="Page to review",
            display="Ada Lovelace",
            address="ada@example.com",
            body="Please look at https://testsafebrowsing.appspot.com/s/phishing.html when you have a moment.",
            headers=_pass_headers("ada@example.com"),
        ),
    },
    {
        "id": "sb-malware",
        "tier": 2,
        "role": "malicious",
        "expect_verdict": "Malicious",
        "min_score": 90,
        "max_score": 100,
        "provider": "safebrowsing",
        "email": _message(
            message_id="sb-malware",
            subject="Page to review",
            display="Ada Lovelace",
            address="ada@example.com",
            body="Please look at https://testsafebrowsing.appspot.com/s/malware.html when you have a moment.",
            headers=_pass_headers("ada@example.com"),
        ),
    },
    {
        "id": "sb-unwanted",
        "tier": 2,
        "role": "malicious",
        "expect_verdict": "Malicious",
        "min_score": 90,
        "max_score": 100,
        "provider": "safebrowsing",
        "email": _message(
            message_id="sb-unwanted",
            subject="Page to review",
            display="Ada Lovelace",
            address="ada@example.com",
            body="Please look at https://testsafebrowsing.appspot.com/s/unwanted.html when you have a moment.",
            headers=_pass_headers("ada@example.com"),
        ),
    },
]


BENIGN_URL_CASES: list[dict] = [
    {
        "id": "benign-github",
        "tier": 2,
        "role": "benign",
        "expect_verdict": "Safe",
        "min_score": 0,
        "max_score": 15,
        "email": _message(
            message_id="benign-github",
            subject="Repository",
            display="Ada Lovelace",
            address="ada@example.com",
            body="The notes are in https://github.com whenever you want them.",
            headers=_pass_headers("ada@example.com"),
        ),
    },
    {
        "id": "benign-example",
        "tier": 2,
        "role": "benign",
        "expect_verdict": "Safe",
        "min_score": 0,
        "max_score": 15,
        "email": _message(
            message_id="benign-example",
            subject="Reference",
            display="Ada Lovelace",
            address="ada@example.com",
            body="The example page is https://example.com if you need a placeholder.",
            headers=_pass_headers("ada@example.com"),
        ),
    },
]
