"""Turn raw email HTML and text into a bounded plain-text body and a URL list."""

from __future__ import annotations

import re
from html.parser import HTMLParser

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_TRAILING_PUNCTUATION = ".,;:!?\"'"


class _HtmlText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.urls: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "noscript"}:
            self._skip += 1
        for key, value in attrs:
            if not value:
                continue
            if key.lower() in {"href", "src"} and not value.lower().strip().startswith("javascript:"):
                self.urls.append(value.strip())

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript"} and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if self._skip or not data:
            return
        self.parts.append(data)


def refang(text: str) -> str:
    if not text:
        return ""
    cleaned = text.replace("hxxps://", "https://").replace("hxxp://", "http://")
    cleaned = cleaned.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    return cleaned


def clean_text(text: str) -> str:
    return _CONTROL_RE.sub("", text or "")


def extract_urls(text: str) -> list[str]:
    found: list[str] = []
    for match in _URL_RE.findall(refang(text or "")):
        url = match.strip().rstrip(_TRAILING_PUNCTUATION)
        if url.lower().startswith(("http://", "https://")):
            found.append(url)
    return found


def html_to_text(html: str) -> tuple[str, list[str]]:
    parser = _HtmlText()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        return clean_text(re.sub(r"<[^>]+>", " ", html or "")), extract_urls(html or "")
    text = clean_text(" ".join(part.strip() for part in parser.parts if part.strip()))
    text = re.sub(r"\s+", " ", text).strip()
    return text, parser.urls + extract_urls(text)


def prepare_content(body_text: str, body_html: str) -> tuple[str, list[str]]:
    """Return sanitized visible text and deduplicated http(s) URLs."""
    text = clean_text(refang(body_text or ""))
    urls = extract_urls(text)
    if body_html:
        html_text, html_urls = html_to_text(refang(body_html))
        urls.extend(html_urls)
        urls.extend(extract_urls(html_text))
        if not text.strip():
            text = html_text
    text = re.sub(r"\s+", " ", text).strip()[:20_000]
    deduped: list[str] = []
    seen: set[str] = set()
    for url in urls:
        key = url.strip()
        if not key or key.lower() in seen:
            continue
        if not key.lower().startswith(("http://", "https://")):
            continue
        seen.add(key.lower())
        deduped.append(key)
        if len(deduped) >= 20:
            break
    return text, deduped
