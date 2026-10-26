"""Brands and domain helpers used by spoofing and lookalike checks."""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import NamedTuple
from urllib.parse import urlparse

_CONFUSABLES = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ї": "i",
        "ѕ": "s",
        "α": "a",
        "β": "b",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "υ": "y",
        "χ": "x",
    }
)

MULTI_PART_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "co.il",
        "org.il",
        "co.jp",
        "com.au",
        "net.au",
        "com.br",
        "co.za",
        "com.mx",
        "co.in",
        "com.tr",
        "co.nz",
    }
)

SECURITY_WORDS = frozenset(
    {
        "secure",
        "security",
        "login",
        "logon",
        "signin",
        "account",
        "accounts",
        "verify",
        "verification",
        "update",
        "support",
        "auth",
        "password",
        "credential",
        "credentials",
        "billing",
        "wallet",
        "unlock",
        "alert",
        "alerts",
        "service",
        "services",
        "team",
        "helpdesk",
        "help",
        "admin",
        "notification",
        "notifications",
        "customer",
        "care",
        "fraud",
        "notice",
        "payment",
        "payments",
        "noreply",
        "info",
        "desk",
        "bank",
    }
)


class Brand(NamedTuple):
    name: str
    aliases: tuple[str, ...]
    domains: frozenset[str]


BRANDS: tuple[Brand, ...] = (
    Brand("Google", ("google",), frozenset({"google.com", "gmail.com", "googlemail.com", "youtube.com"})),
    Brand(
        "Microsoft",
        ("microsoft", "outlook", "office365"),
        frozenset({"microsoft.com", "outlook.com", "office.com", "live.com", "hotmail.com", "office365.com", "microsoftonline.com"}),
    ),
    Brand("Apple", ("apple", "icloud"), frozenset({"apple.com", "icloud.com"})),
    Brand("Amazon", ("amazon",), frozenset({"amazon.com", "amazon.co.uk"})),
    Brand("PayPal", ("paypal",), frozenset({"paypal.com"})),
    Brand("Netflix", ("netflix",), frozenset({"netflix.com"})),
    Brand("Meta", ("facebook", "instagram", "meta"), frozenset({"facebook.com", "fb.com", "instagram.com", "meta.com"})),
    Brand("LinkedIn", ("linkedin",), frozenset({"linkedin.com"})),
    Brand("Dropbox", ("dropbox",), frozenset({"dropbox.com"})),
    Brand("DocuSign", ("docusign",), frozenset({"docusign.com", "docusign.net"})),
    Brand("Adobe", ("adobe",), frozenset({"adobe.com"})),
    Brand("Wells Fargo", ("wellsfargo", "wells fargo"), frozenset({"wellsfargo.com"})),
    Brand("Bank of America", ("bank of america", "bankofamerica", "bofa"), frozenset({"bankofamerica.com", "bofa.com"})),
    Brand("Chase", ("chase",), frozenset({"chase.com"})),
    Brand("DHL", ("dhl",), frozenset({"dhl.com"})),
    Brand("FedEx", ("fedex",), frozenset({"fedex.com"})),
    Brand("UPS", ("ups",), frozenset({"ups.com"})),
    Brand("IRS", ("irs",), frozenset({"irs.gov"})),
)


def fold(text: str) -> str:
    lowered = text.lower().translate(_CONFUSABLES)
    return re.sub(r"[^a-z0-9]+", "", lowered)


def normalize_phrase(text: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", text or "")
    return " ".join(fold(word) for word in words if fold(word))


def email_domain(address: str) -> str:
    if not address:
        return ""
    _, parsed = parseaddr(address)
    candidate = parsed or address
    if "@" not in candidate:
        return ""
    return candidate.split("@", 1)[1].strip().lower().rstrip(".")


def registrable_domain(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if ":" in host:
        host = host.split(":", 1)[0]
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def host_of(url: str) -> str:
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"}:
        return ""
    return (parsed.hostname or "").lower()


def domain_belongs(domain: str, official: frozenset[str]) -> bool:
    host = (domain or "").lower().strip(".")
    if not host:
        return False
    registrable = registrable_domain(host)
    for official_domain in official:
        if host == official_domain or host.endswith("." + official_domain):
            return True
        if registrable == official_domain:
            return True
    return False


def brand_for_domain(domain: str) -> Brand | None:
    for brand in BRANDS:
        if domain_belongs(domain, brand.domains):
            return brand
    return None


def mentions_brand(display_name: str, brand: Brand) -> bool:
    phrase = normalize_phrase(display_name)
    if not phrase:
        return False
    tokens = phrase.split()
    role_language = any(token in SECURITY_WORDS for token in tokens)
    for alias in brand.aliases:
        alias_fold = normalize_phrase(alias)
        if not alias_fold:
            continue
        if " " in alias_fold:
            if alias_fold in phrase:
                return True
            continue
        if alias_fold in tokens and (len(alias_fold) >= 6 or role_language):
            return True
    return False


def levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if abs(len(left) - len(right)) > 2:
        return 3
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for index, char in enumerate(left, start=1):
        current = [index]
        for inner, other in enumerate(right, start=1):
            current.append(
                min(
                    previous[inner] + 1,
                    current[inner - 1] + 1,
                    previous[inner - 1] + (char != other),
                )
            )
        previous = current
    return previous[-1]
