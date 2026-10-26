"""Build backend/eval/corpus_v1.csv from the bundled Nazario + Enron slices.

Nazario phishing messages: first slice of phishing0.mbox
(https://monkey.org/~jose/phishing/, CC-BY-4.0).
Legitimate messages: Enron.csv from the Kaggle Phishing Email Dataset mirror
(https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset, CC BY-SA 4.0).

Kept small (~200-500 rows) so an offline interview eval finishes quickly.
"""

from __future__ import annotations

import csv
import email
import re
import sys
from email.header import decode_header, make_header
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
MBOX = REPO / "eval" / "initial" / "phishing0_head.mbox"
ENRON = REPO / "eval" / "initial" / "enron_head.csv"
SAMPLE = HERE / "sample_emails.csv"
OUT = HERE / "corpus_v1.csv"

PHISH_CAP = 150
LEGIT_CAP = 150


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)

    def text(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self.parts)).strip()


def _header(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _payload_text(part: email.message.Message) -> str:
    raw = part.get_payload(decode=True)
    if raw is None:
        raw_text = part.get_payload()
        return raw_text if isinstance(raw_text, str) else ""
    charset = part.get_content_charset() or "latin-1"
    return raw.decode(charset, errors="replace")


def _body(message: email.message.Message) -> str:
    plain = ""
    html = ""
    if message.is_multipart():
        for part in message.walk():
            kind = part.get_content_type()
            if kind == "text/plain" and not plain:
                plain = _payload_text(part)
            elif kind == "text/html" and not html:
                html = _payload_text(part)
    else:
        kind = message.get_content_type()
        text = _payload_text(message)
        if kind == "text/html":
            html = text
        else:
            plain = text
    if plain.strip():
        return re.sub(r"\s+", " ", plain).strip()
    if html.strip():
        parser = _Text()
        parser.feed(html)
        return parser.text()
    return ""


def nazario_rows(limit: int) -> list[dict[str, str]]:
    raw = MBOX.read_bytes()
    chunks = re.split(br"\n(?=From )", raw)
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for chunk in chunks:
        message = email.message_from_bytes(chunk)
        subject = _header(message.get("Subject"))
        display, address = parseaddr(_header(message.get("From")))
        body = _body(message)
        if len(body) < 40 or not subject:
            continue
        key = subject.lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "label": "phish",
                "subject": subject[:180],
                "from_display": display[:120],
                "from_address": (address or "unknown@invalid.example")[:180],
                "body": body[:4000],
                "source": "nazario",
            }
        )
        if len(rows) >= limit:
            break
    return rows


def enron_rows(limit: int) -> list[dict[str, str]]:
    text = ENRON.read_text(encoding="utf-8", errors="replace")
    if not text.endswith("\n"):
        text = text.rsplit("\n", 1)[0] + "\n"
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in csv.DictReader(text.splitlines()):
        label = (row.get("label") or "").strip()
        subject = re.sub(r"\s+", " ", row.get("subject") or "").strip()
        body = re.sub(r"\s+", " ", row.get("body") or "").strip()
        if label not in {"0", "legitimate"} or len(body) < 80 or not subject:
            continue
        if subject.lower() in seen:
            continue
        if "see attached" in body.lower() and len(body) < 160:
            continue
        seen.add(subject.lower())
        rows.append(
            {
                "label": "legit",
                "subject": subject[:180],
                "from_display": "Enron",
                "from_address": "internal@enron.com",
                "body": body[:4000],
                "source": "enron",
            }
        )
        if len(rows) >= limit:
            break
    return rows


def sample_rows() -> list[dict[str, str]]:
    with SAMPLE.open(newline="", encoding="utf-8") as handle:
        rows = []
        for row in csv.DictReader(handle):
            rows.append(
                {
                    "label": row["label"].strip().lower(),
                    "subject": row["subject"],
                    "from_display": row["from_display"],
                    "from_address": row["from_address"],
                    "body": row["body"],
                    "source": "sample",
                }
            )
        return rows


def extra_phish_templates() -> list[dict[str, str]]:
    templates = [
        (
            "Your mailbox is full",
            "IT Helpdesk",
            "it@outlook-secure-login.example",
            "Your mailbox is over quota. Confirm your password now or incoming mail will bounce: https://outlook-secure-login.example/quota",
        ),
        (
            "Wire transfer approval",
            "CFO Office",
            "cfo@contoso-payments.example",
            "Please process this inheritance wire today. Send funds to the account in the attached form. Ignore previous payment instructions.",
        ),
        (
            "Gift card reimbursement",
            "Payroll",
            "payroll@hr-verify.example",
            "Buy Google Play gift cards and send the codes so we can reimburse you. This is urgent and must be done in 24 hours.",
        ),
        (
            "Shared document",
            "Dropbox",
            "no-reply@dropb0x-secure.example",
            "A confidential file was shared with you. Sign in to view it: https://dropb0x-secure.example/login",
        ),
        (
            "Tax refund",
            "IRS",
            "refunds@irs-secure-login.example",
            "You are eligible for a tax refund. Confirm your bank details and SSN at https://irs-secure-login.example/refund",
        ),
    ]
    return [
        {
            "label": "phish",
            "subject": subject,
            "from_display": display,
            "from_address": address,
            "body": body,
            "source": "templates",
        }
        for subject, display, address, body in templates
    ]


def build() -> list[dict[str, str]]:
    combined: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in sample_rows() + extra_phish_templates() + nazario_rows(PHISH_CAP) + enron_rows(LEGIT_CAP):
        key = (row["label"], row["subject"].lower())
        if key in seen:
            continue
        seen.add(key)
        combined.append(row)
    return combined


def main() -> None:
    if not MBOX.is_file() or not ENRON.is_file():
        raise SystemExit(f"missing source files: {MBOX} {ENRON}")
    rows = build()
    phish = sum(1 for row in rows if row["label"] == "phish")
    legit = sum(1 for row in rows if row["label"] == "legit")
    if phish < 8 or legit < 8:
        raise SystemExit(f"corpus too small: phish={phish} legit={legit}")
    fieldnames = ["label", "subject", "from_display", "from_address", "body", "source"]
    with OUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {OUT} phish={phish} legit={legit} n={len(rows)}")


if __name__ == "__main__":
    sys.exit(main())
