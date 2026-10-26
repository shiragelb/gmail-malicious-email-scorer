"""Score a small public sample from the sources named in testing.md section 3.

Nazario phishing messages come from the first slice of phishing0.mbox
(https://monkey.org/~jose/phishing/, CC-BY-4.0). Legitimate messages come
from the first slice of Enron.csv in the Kaggle Phishing Email Dataset mirror
(https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset, CC BY-SA 4.0).
"""

from __future__ import annotations

import csv
import email
import json
import re
from email.header import decode_header, make_header
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
MBOX = HERE / "phishing0_head.mbox"
ENRON = HERE / "enron_head.csv"
OUT = HERE / "results.json"
ENDPOINT = "http://127.0.0.1:8000/v1/analyze"
PHISH_N = 5
LEGIT_N = 5


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


def nazario_messages() -> list[dict]:
    raw = MBOX.read_bytes()
    chunks = re.split(br"\n(?=From )", raw)
    if chunks and not raw.endswith(b"\n\n"):
        chunks = chunks[:-1]
    rows: list[dict] = []
    seen: set[str] = set()
    for chunk in chunks:
        message = email.message_from_bytes(chunk)
        subject = _header(message.get("Subject"))
        display, address = parseaddr(_header(message.get("From")))
        body = _body(message)
        if len(body) < 40 or not subject or subject.lower() in seen:
            continue
        seen.add(subject.lower())
        rows.append(
            {
                "source": "Nazario phishing0.mbox",
                "label": "phish",
                "subject": subject[:180],
                "from_display": display[:120],
                "from_address": address[:180],
                "body": body[:4000],
            }
        )
        if len(rows) >= PHISH_N:
            break
    return rows


def enron_messages() -> list[dict]:
    text = ENRON.read_text(encoding="utf-8", errors="replace")
    if not text.endswith("\n"):
        text = text.rsplit("\n", 1)[0] + "\n"
    rows: list[dict] = []
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
                "source": "Kaggle Enron.csv",
                "label": "legit",
                "subject": subject[:180],
                "from_display": "",
                "from_address": "",
                "body": body[:4000],
            }
        )
        if len(rows) >= LEGIT_N:
            break
    return rows


def score(client: httpx.Client, row: dict) -> dict:
    payload = {
        "subject": row["subject"],
        "from_display": row["from_display"],
        "from_address": row["from_address"],
        "body_text": row["body"],
    }
    response = client.post(ENDPOINT, json=payload, timeout=90)
    response.raise_for_status()
    data = response.json()
    layers = data.get("layers") or {}
    urls = layers.get("urls") or {}
    meta = layers.get("meta") or {}
    text = layers.get("text") or {}
    matches = [
        {"provider": item.get("provider"), "threat": item.get("threat")}
        for item in urls.get("matches") or []
    ]
    return {
        "source": row["source"],
        "label": row["label"],
        "subject": row["subject"],
        "from_display": row["from_display"],
        "from_address": row["from_address"],
        "excerpt": row["body"][:180],
        "score": data["score"],
        "verdict": data["verdict"],
        "summary": data["summary"],
        "reasons": [item["text"] for item in data.get("reasons") or []][:4],
        "engine": meta.get("engine"),
        "band": meta.get("band"),
        "text_model": text.get("model"),
        "text_phishing": text.get("is_phishing"),
        "url_matches": matches,
        "url_unavailable": urls.get("unavailable") or [],
        "urls_checked": len(urls.get("checked") or []),
    }


def main() -> None:
    rows = nazario_messages() + enron_messages()
    if len(rows) < PHISH_N + LEGIT_N:
        raise SystemExit(f"only parsed {len(rows)} emails")
    results = []
    with httpx.Client() as client:
        for index, row in enumerate(rows, start=1):
            print(f"{index}/{len(rows)} {row['label']} {row['subject'][:60]}", flush=True)
            results.append(score(client, row))
    OUT.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
