"""The three live-demo emails from the testing plan."""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas import EmailInput

_PASS = (
    "mx.google.com; spf=pass smtp.mailfrom={address}; "
    "dkim=pass header.i=@{domain}; dmarc=pass header.from={domain}"
)


class Scenario(BaseModel):
    id: str
    title: str
    narrative: str
    expected_min: int
    expected_max: int
    expected_verdict: str
    email: EmailInput = Field()


def _pass_headers(address: str) -> dict[str, str]:
    domain = address.split("@", 1)[1]
    return {"Authentication-Results": _PASS.format(address=address, domain=domain)}


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="A",
        title="Legitimate email",
        narrative="Trusted domain, passing SPF/DKIM/DMARC, and a clean link.",
        expected_min=0,
        expected_max=15,
        expected_verdict="Safe",
        email=EmailInput(
            message_id="scenario-a",
            subject="Planning notes",
            from_display="Jordan Lee",
            from_address="jordan.lee@gmail.com",
            body_text=(
                "Hi Priya, thanks for sending the notes from yesterday's planning meeting. "
                "Thursday at 2pm still works for me. I put the agenda on the calendar: "
                "https://calendar.google.com/calendar/u/0/r See you then, Jordan"
            ),
            headers=_pass_headers("jordan.lee@gmail.com"),
        ),
    ),
    Scenario(
        id="B",
        title="Classic phishing",
        narrative="Failed authentication, a brand impersonation, and the reserved URLhaus test URL.",
        expected_min=85,
        expected_max=100,
        expected_verdict="Malicious",
        email=EmailInput(
            message_id="scenario-b",
            subject="Your account will be suspended",
            from_display="Google Security",
            from_address="attacker@malicious-domain.ru",
            body_text=(
                "Google Security alert: your account will be suspended within 24 hours. "
                "Verify your password immediately: http://malicious-test-url.com/login"
            ),
            headers={
                "Authentication-Results": (
                    "mx.example.com; spf=fail smtp.mailfrom=malicious-domain.ru; "
                    "dkim=fail header.i=@malicious-domain.ru; dmarc=fail header.from=malicious-domain.ru"
                ),
                "Received-SPF": "fail (malicious-domain.ru does not designate the sending host)",
            },
        ),
    ),
    Scenario(
        id="C",
        title="Targeted phishing",
        narrative="Passing authentication, with a polite credential request on a lookalike link.",
        expected_min=60,
        expected_max=80,
        expected_verdict="Suspicious",
        email=EmailInput(
            message_id="scenario-c",
            subject="Quick confirmation on your account access",
            from_display="Alex Morgan",
            from_address="alex.morgan@contoso.com",
            body_text=(
                "Hi Alex, I hope you're doing well. Our identity provider is rotating credentials this week, "
                "and your mailbox is on the list. When you have a moment, could you confirm your password here "
                "so access isn't interrupted: https://contoso-account-secure.com/login Thank you, IT Helpdesk"
            ),
            headers=_pass_headers("alex.morgan@contoso.com"),
        ),
    ),
)


def scenario_by_id(scenario_id: str) -> Scenario | None:
    for scenario in SCENARIOS:
        if scenario.id.lower() == scenario_id.lower():
            return scenario
    return None
