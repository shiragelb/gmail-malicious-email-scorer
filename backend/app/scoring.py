"""Combine layer findings into a 0-100 score and a Safe / Suspicious / Malicious verdict."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.schemas import CheckItem, Finding, Reason, Verdict

_IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".heic", ".tif", ".tiff")
_DOC_TYPES = frozenset({"pdf", "office", "office_zip", "zip", "ole", "rtf"})

_UI_SKIP_CODES = frozenset(
    {
        "llm_reason",
        "llm_guardrail",
        "text_pressure",
        "dns_published",
        "attachment_pressure",
    }
)

LAYER_CAPS = {
    "authentication": 30,
    "identity": 30,
    "url": 35,
    "text": 28,
    "attachment": 35,
    "correlation": 20,
}

VERDICT_SUSPICIOUS = 40
VERDICT_MALICIOUS = 85


@dataclass
class SignalFlags:
    auth_failed: bool = False
    auth_passed: bool = False
    new_sender_domain: bool = False
    spoofing: bool = False
    lookalike: bool = False
    intel_hit: bool = False
    semantic_phish: bool = False
    severe_text: bool = False
    link_mismatch: bool = False
    file_active: bool = False


@dataclass
class ScoreDecision:
    score: int
    verdict: Verdict
    band: str
    summary: str
    findings: list[Finding] = field(default_factory=list)
    analyst: dict[str, Any] | None = None


def verdict_for(score: int) -> Verdict:
    if score >= VERDICT_MALICIOUS:
        return "Malicious"
    if score >= VERDICT_SUSPICIOUS:
        return "Suspicious"
    return "Safe"


def color_for(verdict: Verdict) -> str:
    return {"Safe": "green", "Suspicious": "amber", "Malicious": "red"}[verdict]


def capped_raw(findings: list[Finding]) -> int:
    totals: dict[str, int] = {}
    for finding in findings:
        if finding.points > 0 and finding.polarity == "risk":
            totals[finding.layer] = totals.get(finding.layer, 0) + finding.points
    raw = 0
    for layer, points in totals.items():
        raw += min(points, LAYER_CAPS.get(layer, points))
    return min(100, raw)


def summarize(verdict: Verdict, flags: SignalFlags) -> str:
    if verdict == "Malicious":
        if flags.intel_hit:
            return "This is very likely dangerous. A security list has already seen a link or file from this message used in attacks."
        return "This is very likely a fake. It pretends to be someone it is not, and the sender checks failed."
    if verdict == "Suspicious":
        if flags.file_active:
            return "Treat this as suspicious: an attached file can run hidden code. Confirm the sender another way before opening it."
        if flags.semantic_phish and (flags.lookalike or flags.new_sender_domain or flags.link_mismatch):
            return "Treat this as suspicious: it asks you to sign in on a website that is not the real company's site."
        if flags.severe_text:
            return "Treat this as suspicious: it reads like a classic scam promising money or asking you to send funds."
        return "Treat this as suspicious. It is not a confirmed attack, but skip the links until you check another way."
    if flags.semantic_phish and not flags.severe_text:
        return (
            "This looks mostly fine. It asks you to change a password, which real companies also do. "
            "If you were not expecting it, open the company's app or website yourself instead of tapping the email link."
        )
    if flags.auth_passed:
        return "This looks like a genuine email from a real sender. Nothing here looks like a scam."
    return "Nothing here looks like a scam."


def decide(findings: list[Finding], flags: SignalFlags) -> ScoreDecision:
    raw = capped_raw(findings)
    score = raw
    band = "blended"

    clean = not any(
        (
            flags.auth_failed,
            flags.new_sender_domain,
            flags.spoofing,
            flags.lookalike,
            flags.intel_hit,
            flags.link_mismatch,
            flags.file_active,
            flags.semantic_phish,
            flags.severe_text,
        )
    )

    if flags.intel_hit:
        score = min(100, max(raw, 90))
        band = "confirmed"
    elif flags.auth_failed and flags.spoofing and (flags.semantic_phish or flags.new_sender_domain or flags.lookalike):
        score = min(100, max(raw, 88))
        band = "deterministic"
    elif flags.auth_failed and flags.new_sender_domain and (flags.spoofing or flags.lookalike):
        score = min(100, max(raw, 88))
        band = "deterministic"
    elif flags.file_active and not flags.intel_hit:
        score = min(80, max(raw, 60))
        band = "attachment"
        findings = [
            *findings,
            Finding(
                layer="correlation",
                code="attachment_pressure",
                polarity="risk",
                text=(
                    "An attachment shows active or disguised content. "
                    "That is enough for Suspicious until a threat feed confirms the file or a link inside it."
                ),
                points=0,
            ),
        ]
    elif (
        flags.semantic_phish
        and not flags.auth_failed
        and not flags.intel_hit
        and (flags.lookalike or flags.new_sender_domain or flags.link_mismatch)
    ):
        score = min(80, max(raw, 64))
        band = "semantic"
    elif flags.severe_text and not flags.intel_hit:
        score = min(70, max(raw, 48))
        band = "text"
        findings = [
            *findings,
            Finding(
                layer="correlation",
                code="text_pressure",
                polarity="risk",
                text=(
                    "The wording matches a classic money or inheritance scam. "
                    "That is enough to treat the message as suspicious, not malicious, "
                    "until a threat feed or failed authentication agrees."
                ),
                points=0,
            ),
        ]
    elif flags.semantic_phish and not flags.intel_hit:
        score = min(raw, 35)
        band = "credential"
    elif clean:
        score = min(raw, 12)
        band = "trusted" if flags.auth_passed else "clean"

    score = max(0, min(100, score))
    verdict = verdict_for(score)
    return ScoreDecision(
        score=score,
        verdict=verdict,
        band=band,
        summary=summarize(verdict, flags),
        findings=list(findings),
    )


def apply_guardrails(local: ScoreDecision, proposed: int) -> int:
    """Keep an external model inside the band the deterministic evidence supports."""
    proposed = max(0, min(100, int(proposed)))
    if local.band == "confirmed":
        return min(100, max(proposed, 90))
    if local.band == "deterministic":
        return min(100, max(proposed, 88))
    if local.band in {"semantic", "attachment"}:
        return min(80, max(proposed, 60))
    if local.band == "text":
        return min(70, max(proposed, 48))
    if local.band == "credential":
        return min(proposed, 35)
    if local.band in {"trusted", "clean"}:
        return min(proposed, 15)
    return proposed


def mitigations_for(
    verdict: Verdict,
    *,
    file_active: bool = False,
    credential_ask: bool = False,
) -> list[str]:
    if verdict == "Malicious":
        items = [
            "Do not tap links, open files, reply, or forward this message.",
            "Use Report phishing and Block sender if you agree it is fake.",
        ]
    elif verdict == "Suspicious":
        items = [
            "Check this request in the company's real app or a phone number you already have, not through this email.",
            "Do not type a password or a one-time code on a page opened from this message.",
        ]
        if file_active:
            items.insert(
                0,
                "Do not open the attachment until you confirm the sender another way.",
            )
    elif credential_ask:
        items = [
            "If you did not ask to change a password, open the company's app or website yourself.",
        ]
    else:
        items = [
            "Still pause if a message asks you to change payment details or open a surprising file.",
        ]
    items.append("This is a helpful check, not a guarantee.")
    return items[:3]


def public_reasons(findings: list[Finding]) -> list[Reason]:
    """Short score explanation for the sidebar. Analyst notes stay off this list."""
    risks: list[Finding] = []
    trusts: list[Finding] = []
    notes: list[Finding] = []
    for item in findings:
        if not item.text or item.code in _UI_SKIP_CODES:
            continue
        text = _public_text(item)
        if not text:
            continue
        trimmed = Finding(
            layer=item.layer,
            code=item.code,
            polarity=item.polarity,
            text=text,
            points=item.points,
        )
        if item.polarity == "risk":
            risks.append(trimmed)
        elif item.polarity == "trust":
            trusts.append(trimmed)
        else:
            notes.append(trimmed)
    risks.sort(key=lambda item: item.points, reverse=True)
    risks = _collapse_auth_failures(risks)
    groups = (
        [item for item in risks if item.code.startswith("intel_")],
        [item for item in risks if item.layer == "authentication"],
        [item for item in risks if item.layer == "identity" or item.code in {"lookalike", "link_mismatch", "semantic_mismatch"}],
        [item for item in risks if item.layer == "text" or item.code in {"text_classifier", "attachment_text"}],
        [item for item in risks if item.layer == "attachment"],
        risks,
    )
    chosen: list[Finding] = []
    seen: set[int] = set()
    for group in groups:
        for item in group:
            if id(item) in seen:
                continue
            chosen.append(item)
            seen.add(id(item))
            break
        if len(chosen) >= 4:
            break
    priority_notes = [
        item for item in notes if item.code in {"intel_unavailable", "hash_intel_unavailable", "prompt_injection"}
    ]
    other_notes = [item for item in notes if item not in priority_notes]
    if len(chosen) < 3:
        chosen.extend(trusts[:1])
    if len(chosen) < 3:
        chosen.extend((priority_notes + other_notes)[:1])
    return [Reason(polarity=item.polarity, text=item.text, layer=item.layer) for item in _dedupe_reasons(chosen)[:3]]


def _collapse_auth_failures(risks: list[Finding]) -> list[Finding]:
    fails = [item for item in risks if item.code in {"spf_fail", "dkim_fail", "dmarc_fail"}]
    if len(fails) < 2:
        return risks
    merged = Finding(
        layer="authentication",
        code="auth_fail",
        polarity="risk",
        text="The usual checks could not prove this email really came from who it claims.",
        points=max(item.points for item in fails),
    )
    kept = [item for item in risks if item.code not in {"spf_fail", "dkim_fail", "dmarc_fail"}]
    return [merged, *kept]


def _dedupe_reasons(items: list[Finding]) -> list[Finding]:
    unique: list[Finding] = []
    seen: list[str] = []
    for item in items:
        norm = "".join(ch for ch in item.text.lower() if ch.isalnum() or ch.isspace())
        norm = " ".join(norm.split())
        if any(norm in previous or previous in norm for previous in seen):
            continue
        unique.append(item)
        seen.append(norm)
    return unique


def _public_text(item: Finding) -> str:
    blob = item.text.lower()
    if item.code in {"domain_age"} and item.polarity == "trust":
        return ""
    if item.code in {"domain_age", "new_domain", "new_link_domain"}:
        if "year" in blob:
            return ""
        return "This sender's email address is very new, which scammers often use."
    if item.code == "auth_pass":
        return "This message really came from the named sender."
    if item.code in {"spf_pass", "dkim_pass", "dmarc_pass"}:
        return ""
    if item.code in {"spf_fail", "dkim_fail", "dmarc_fail", "auth_fail", "spf_softfail"}:
        return "The usual checks could not prove this email really came from who it claims."
    if item.code == "auth_missing":
        return ""
    if item.code in {"intel_unavailable", "hash_intel_unavailable"}:
        return "A security check timed out. That did not change the score."
    if item.code.startswith("intel_"):
        return "A security list has already flagged a link or file in this message as dangerous."
    if item.code == "spoofing":
        return item.text.replace("Display name claims", "The name on the email says").replace(
            "but the sending domain is", "but it did not come from"
        )
    if item.code == "lookalike":
        return "The link looks like a fake copy of the real company's website."
    if item.code == "link_mismatch":
        return "A link goes to a different website than the sender, and it looks like a sign-in page."
    if item.code in {"text_classifier", "attachment_text"}:
        prefix = "A file attached to this email: " if item.code == "attachment_text" else ""
        if any(token in blob for token in ("inheritance", "relative", "lottery", "gift card", "wire", "farm", "ranch")):
            return prefix + "The wording matches a classic money or inheritance scam."
        if any(token in blob for token in ("password", "credentials", "account", "one-time")):
            return prefix + "It asks you to change a password or confirm an account."
        if "urgent" in blob or "deadline" in blob:
            return prefix + "The wording is urgent, which is weak on its own."
        return prefix + "The wording has some scam-like phrasing." if prefix else ""
    if item.code == "semantic_mismatch":
        return "It asks you to sign in on a website that does not belong to the sender."
    if item.code == "prompt_injection":
        return "This message tries to give instructions to an AI. Those instructions were ignored."
    if "spf" in blob or "dkim" in blob or "dmarc" in blob:
        if "pass" in blob:
            return "This message really came from the named sender."
        if "fail" in blob:
            return "The usual checks could not prove this email really came from who it claims."
    if "registered for" in blob or "years" in blob:
        return ""
    return item.text.strip()[:180]


def suggested_actions(verdict: Verdict) -> list[str]:
    del verdict
    return ["report_phishing", "block_sender"]


def build_checks(
    flags: SignalFlags,
    *,
    url_count: int = 0,
    url_flagged: int = 0,
    attachment_reports: list[dict] | None = None,
    attachment_names: list[str] | None = None,
    wording_severe: bool = False,
    wording_credential: bool = False,
) -> list[CheckItem]:
    """Plain-language checklist of what the scorer looked at."""
    checks: list[CheckItem] = []

    if flags.auth_failed or flags.spoofing:
        checks.append(
            CheckItem(
                id="sender",
                label="Sender",
                detail="Could not confirm this really came from who it claims.",
                status="fail",
            )
        )
    elif flags.auth_passed:
        checks.append(
            CheckItem(
                id="sender",
                label="Sender",
                detail="Confirmed as the named sender.",
                status="pass",
            )
        )
    else:
        checks.append(
            CheckItem(
                id="sender",
                label="Sender",
                detail="Sender checks were incomplete, so this was not treated as a failure.",
                status="warn",
            )
        )
    # #region agent log
    try:
        import json
        import time
        from pathlib import Path

        _log = Path(__file__).resolve().parents[2] / "debug-9947bd.log"
        with _log.open("a", encoding="utf-8") as _fh:
            _fh.write(
                json.dumps(
                    {
                        "sessionId": "9947bd",
                        "runId": "pre-fix",
                        "hypothesisId": "E",
                        "location": "scoring.py:build_checks",
                        "message": "sender check row chosen",
                        "data": {
                            "auth_passed": flags.auth_passed,
                            "auth_failed": flags.auth_failed,
                            "spoofing": flags.spoofing,
                            "sender_status": checks[0].status,
                            "sender_detail": checks[0].detail,
                        },
                        "timestamp": int(time.time() * 1000),
                    },
                    ensure_ascii=True,
                )
                + "\n"
            )
    except Exception:
        pass
    # #endregion

    if url_count <= 0:
        checks.append(
            CheckItem(
                id="links",
                label="Links",
                detail="No links in this message.",
                status="skip",
            )
        )
    elif url_flagged or flags.lookalike or flags.link_mismatch or flags.intel_hit:
        checks.append(
            CheckItem(
                id="links",
                label="Links",
                detail=_count_phrase(url_count, "link", "links") + " checked — one or more look risky.",
                status="fail" if flags.intel_hit else "warn",
            )
        )
    else:
        checks.append(
            CheckItem(
                id="links",
                label="Links",
                detail=_count_phrase(url_count, "link", "links") + " checked — nothing flagged.",
                status="pass",
            )
        )

    reports = attachment_reports or []
    names = attachment_names or []
    image_names = [name for name in names if _is_image_name(name)]
    inspected = [report for report in reports if report.get("detected_type") in _DOC_TYPES or report.get("sha256")]
    pdfs = [report for report in inspected if report.get("detected_type") == "pdf"]
    office = [
        report
        for report in inspected
        if report.get("detected_type") in {"office", "office_zip", "ole", "rtf"}
    ]
    active = [report for report in inspected if report.get("active")]
    hash_hit = any((report.get("malwarebazaar") or {}).get("matched") for report in reports)

    if not inspected and not names:
        checks.append(
            CheckItem(
                id="files",
                label="Files",
                detail="No attachments.",
                status="skip",
            )
        )
    elif inspected:
        parts = []
        if pdfs:
            parts.append(_count_phrase(len(pdfs), "PDF", "PDFs"))
        if office:
            parts.append(_count_phrase(len(office), "Office file", "Office files"))
        other = len(inspected) - len(pdfs) - len(office)
        if other > 0:
            parts.append(_count_phrase(other, "file", "files"))
        label = " and ".join(parts) if parts else _count_phrase(len(inspected), "file", "files")
        if hash_hit or active:
            checks.append(
                CheckItem(
                    id="files",
                    label="Files",
                    detail=f"{label} checked — active or known-bad content found.",
                    status="fail" if hash_hit else "warn",
                )
            )
        else:
            checks.append(
                CheckItem(
                    id="files",
                    label="Files",
                    detail=f"{label} checked — no active content found.",
                    status="pass",
                )
            )
    else:
        checks.append(
            CheckItem(
                id="files",
                label="Files",
                detail="Attachments were listed but none were opened for content checks.",
                status="skip",
            )
        )

    if image_names:
        checks.append(
            CheckItem(
                id="pictures",
                label="Pictures",
                detail=_count_phrase(len(image_names), "picture", "pictures")
                + " found — pictures are not opened (only documents are).",
                status="skip",
            )
        )
    else:
        checks.append(
            CheckItem(
                id="pictures",
                label="Pictures",
                detail="No pictures attached.",
                status="skip",
            )
        )

    if wording_severe:
        checks.append(
            CheckItem(
                id="wording",
                label="Wording",
                detail="Reads like a classic money or inheritance scam.",
                status="warn",
            )
        )
    elif wording_credential:
        checks.append(
            CheckItem(
                id="wording",
                label="Wording",
                detail="Asks you to change a password or confirm an account.",
                status="warn",
            )
        )
    else:
        checks.append(
            CheckItem(
                id="wording",
                label="Wording",
                detail="No scam-like phrases stood out.",
                status="pass",
            )
        )

    return checks


def _count_phrase(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _is_image_name(name: str) -> bool:
    lower = (name or "").lower()
    return any(lower.endswith(suffix) for suffix in _IMAGE_SUFFIXES)
