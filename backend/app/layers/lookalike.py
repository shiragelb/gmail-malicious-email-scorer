"""Lookalike and credential-link checks. Homoglyph folding stands in for a live dnstwist scan."""

from __future__ import annotations

import re

from app.brands import (
    BRANDS,
    SECURITY_WORDS,
    brand_for_domain,
    email_domain,
    fold,
    host_of,
    levenshtein,
    mentions_brand,
    normalize_phrase,
    registrable_domain,
)
from app.schemas import Finding

_CREDENTIAL_PATH = re.compile(
    r"(login|logon|signin|sign-in|verify|verification|account|password|credential|webscr)",
    re.IGNORECASE,
)


def _parts(host: str) -> list[str]:
    registrable = registrable_domain(host)
    sld = registrable.split(".")[0] if registrable else ""
    raw_parts = re.split(r"[^a-z0-9]+", sld.lower())
    return [part for part in raw_parts if part]


def assess_url(url: str, sender_domain: str, display_name: str, subject: str) -> list[Finding]:
    host = host_of(url)
    if not host or _is_official(host):
        return []

    findings: list[Finding] = []
    folded_parts = [fold(part) for part in _parts(host)]
    mentioned = _mentioned_brands(display_name, subject)
    sender_stem = fold(registrable_domain(sender_domain).split(".")[0]) if sender_domain else ""

    lookalike_reason = _lookalike_reason(host, folded_parts, sender_domain, sender_stem, mentioned)
    if lookalike_reason:
        findings.append(
            Finding(
                layer="url",
                code="lookalike",
                polarity="risk",
                text=lookalike_reason,
                points=22,
            )
        )

    sender_reg = registrable_domain(sender_domain) if sender_domain else ""
    host_reg = registrable_domain(host)
    if sender_reg and host_reg != sender_reg and _CREDENTIAL_PATH.search(url):
        findings.append(
            Finding(
                layer="url",
                code="link_mismatch",
                polarity="risk",
                text=(
                    f"A link points at {host}, which is not the sender domain {sender_reg}, "
                    "and the path looks like a login or account page."
                ),
                points=14,
            )
        )
    return findings


def _is_official(host: str) -> bool:
    return brand_for_domain(host) is not None


def _mentioned_brands(display_name: str, subject: str) -> set[str]:
    text = f"{display_name} {subject}"
    names: set[str] = set()
    for brand in BRANDS:
        if mentions_brand(text, brand):
            names.add(brand.name)
            names.update(normalize_phrase(alias) for alias in brand.aliases)
    return names


def _lookalike_reason(
    host: str,
    folded_parts: list[str],
    sender_domain: str,
    sender_stem: str,
    mentioned: set[str],
) -> str:
    securityish = any(part in SECURITY_WORDS or fold(part) in SECURITY_WORDS for part in _parts(host))
    for brand in BRANDS:
        stems = [fold(alias) for alias in brand.aliases if " " not in alias]
        for stem in stems:
            if not stem:
                continue
            if stem in folded_parts:
                return f"The link host {host} imitates {brand.name}."
            if any(stem in part and securityish for part in folded_parts):
                return f"The link host {host} imitates {brand.name} and uses account or security wording."
            compact = "".join(folded_parts)
            if mentioned and stem in mentioned and len(stem) >= 6 and levenshtein(compact, stem) <= 1:
                return f"The link host {host} is a lookalike of {brand.name}."

    if sender_stem and len(sender_stem) >= 4 and securityish:
        if sender_stem in folded_parts and "".join(folded_parts) != sender_stem:
            sender_name = registrable_domain(sender_domain) or sender_stem
            return (
                f"The link host {host} imitates the sender domain {sender_name} "
                "and uses account or security wording."
            )
    return ""


def reply_to_mismatch(from_address: str, reply_to: str) -> Finding | None:
    reply_domain = email_domain(reply_to)
    from_domain = email_domain(from_address)
    if not reply_domain or not from_domain:
        return None
    if registrable_domain(reply_domain) == registrable_domain(from_domain):
        return None
    return Finding(
        layer="identity",
        code="reply_to_mismatch",
        polarity="risk",
        text=f"Reply-To uses {reply_domain}, which is different from the From domain {from_domain}.",
        points=10,
    )
