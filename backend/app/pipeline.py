"""Run the analysis layers and fuse them into one verdict."""

from __future__ import annotations

import asyncio
import logging

import httpx

from app.brands import email_domain, registrable_domain
from app.layers import (
    attachments,
    authentication,
    domain_age,
    file_inspect,
    hash_intel,
    lookalike,
    meta_analyst,
    spoofing,
    text_classifier,
    url_intel,
)
from app.sanitize import prepare_content
from app.schemas import AnalysisResponse, EmailInput, Finding, UrlIntelReport, UrlMatch
from app.scoring import (
    SignalFlags,
    build_checks,
    capped_raw,
    color_for,
    decide,
    mitigations_for,
    public_reasons,
    suggested_actions,
    summarize,
)

logger = logging.getLogger(__name__)


async def analyze_email(
    email: EmailInput,
    *,
    client: httpx.AsyncClient | None = None,
    url_screen=None,
    hash_lookup=None,
) -> AnalysisResponse:
    body, urls = prepare_content(email.body_text, email.body_html)
    auth = authentication.assess(email.headers)
    sender = email_domain(email.from_address)
    spoof = spoofing.detect_display_name_spoof(email.from_display, email.from_address)
    age = await _sender_age(sender)
    text = text_classifier.classify(email.subject, body)

    findings: list[Finding] = []
    findings.extend(auth.findings)
    if spoof.spoofing_detected and spoof.reason:
        findings.append(
            Finding(
                layer="identity",
                code="spoofing",
                polarity="risk",
                text=spoof.reason,
                points=spoof.points,
            )
        )
    if age.reason and age.age_days is not None:
        findings.append(
            Finding(
                layer="identity",
                code="new_domain" if age.is_new_domain else "domain_age",
                polarity="risk" if age.points else "trust",
                text=age.reason,
                points=age.points,
            )
        )

    reply = lookalike.reply_to_mismatch(email.from_address, email.reply_to)
    if reply is not None:
        findings.append(reply)

    for url in urls:
        findings.extend(lookalike.assess_url(url, sender, email.from_display, email.subject))

    if domain_age.whois_available():
        findings.extend(await _url_domain_ages(urls, sender))

    findings.extend(attachments.assess(email.attachment_names))

    file_result = file_inspect.inspect_attachments(email.attachments)
    findings.extend(file_result.findings)
    file_urls = file_result.urls
    for url in file_urls:
        findings.extend(lookalike.assess_url(url, sender, email.from_display, email.subject))

    file_text = file_result.text
    file_text_assessment = None
    if file_text:
        file_text_assessment = text_classifier.classify(email.subject, file_text)
        if file_text_assessment.is_phishing or file_text_assessment.points:
            indicator_text = (
                " ".join(file_text_assessment.indicators)
                if file_text_assessment.indicators
                else "The attachment wording has phishing traits."
            )
            findings.append(
                Finding(
                    layer="text",
                    code="attachment_text",
                    polarity="risk" if file_text_assessment.points else "note",
                    text=f"Inside an attachment: {indicator_text}",
                    points=file_text_assessment.points,
                )
            )

    if text.points or text.indicators:
        indicator_text = " ".join(text.indicators) if text.indicators else "The wording has mild phishing traits."
        findings.append(
            Finding(
                layer="text",
                code="text_classifier",
                polarity="risk" if text.points else "note",
                text=indicator_text,
                points=text.points,
            )
        )

    combined_urls = _merge_urls(urls, file_urls)
    intel, intel_failed = await _screen(combined_urls, client=client, url_screen=url_screen)
    for match in intel.matches:
        findings.append(
            Finding(
                layer="url",
                code=f"intel_{match.provider}",
                polarity="risk",
                text=match.detail,
                points=match.points,
            )
        )
    if intel_failed or any(item.endswith("_error") for item in intel.unavailable):
        findings.append(
            Finding(
                layer="url",
                code="intel_unavailable",
                polarity="note",
                text="A threat-intelligence feed timed out or returned an error. No penalty was added for that outage.",
                points=0,
            )
        )

    hashes = [report.sha256 for report in file_result.reports if report.sha256]
    hash_matches, hash_unavailable = await _hash_screen(hashes, client=client, hash_lookup=hash_lookup)
    for match in hash_matches:
        findings.append(
            Finding(
                layer="attachment",
                code=f"intel_{match.provider}",
                polarity="risk",
                text=match.detail,
                points=match.points,
            )
        )
    if any(item.endswith("_error") for item in hash_unavailable):
        findings.append(
            Finding(
                layer="attachment",
                code="hash_intel_unavailable",
                polarity="note",
                text="MalwareBazaar timed out or returned an error. No penalty was added for that outage.",
                points=0,
            )
        )

    published = await _published_dns(sender)
    if published:
        findings.append(
            Finding(
                layer="authentication",
                code="dns_published",
                polarity="note",
                text="Live DNS was consulted only to see whether the sender domain publishes SPF or DMARC. The message score uses the authentication results from the received headers.",
                points=0,
            )
        )

    semantic_phish = text.is_phishing or bool(file_text_assessment and file_text_assessment.is_phishing)
    severe_text = text.is_severe or bool(file_text_assessment and file_text_assessment.is_severe)
    flags = SignalFlags(
        auth_failed=any(result == "fail" for result in (auth.spf, auth.dkim, auth.dmarc)),
        auth_passed=auth.spf == "pass" and auth.dkim == "pass" and auth.dmarc == "pass",
        new_sender_domain=age.is_new_domain,
        spoofing=spoof.spoofing_detected,
        lookalike=any(item.code == "lookalike" for item in findings),
        intel_hit=intel.matched or any(match.confirmed for match in hash_matches),
        semantic_phish=semantic_phish,
        severe_text=severe_text,
        link_mismatch=any(item.code == "link_mismatch" for item in findings),
        file_active=file_result.active,
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
                        "location": "pipeline.py:flags",
                        "message": "auth flags driving sender checklist",
                        "data": {
                            "spf": auth.spf,
                            "dkim": auth.dkim,
                            "dmarc": auth.dmarc,
                            "auth_source": auth.source,
                            "auth_passed": flags.auth_passed,
                            "auth_failed": flags.auth_failed,
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

    if (
        flags.semantic_phish
        and not flags.auth_failed
        and not flags.intel_hit
        and (flags.lookalike or flags.new_sender_domain or flags.link_mismatch)
    ):
        findings.append(
            Finding(
                layer="correlation",
                code="semantic_mismatch",
                polarity="risk",
                text=(
                    "Technical authentication did not fail, but the credential request does not match the link. "
                    "Treated as targeted phishing rather than a confirmed malware payload."
                ),
                points=8,
            )
        )

    decision = decide(findings, flags)
    if decision.band == "confirmed" and decision.score > capped_raw(findings):
        decision.findings.append(
            Finding(
                layer="correlation",
                code="intel_floor",
                polarity="risk",
                text="A confirmed threat-intelligence hit places the message in the malicious band.",
                points=0,
            )
        )

    engine = "local"
    if client is not None:
        decision, engine = await meta_analyst.refine(decision, email, body, client=client)
        decision = type(decision)(
            score=decision.score,
            verdict=decision.verdict,
            band=decision.band,
            summary=summarize(decision.verdict, flags),
            findings=decision.findings,
            analyst=decision.analyst,
        )

    logger.info(
        "scored score=%s verdict=%s band=%s engine=%s",
        decision.score,
        decision.verdict,
        decision.band,
        engine,
    )
    if decision.analyst:
        logger.info(
            "analyst_score=%s analyst_summary=%s",
            decision.analyst.get("score"),
            str(decision.analyst.get("summary") or "")[:240],
        )
    attachment_layers = []
    for report in file_result.reports:
        payload = report.to_layer_dict()
        payload["malwarebazaar"] = next(
            (
                {"matched": True, "threat": match.threat, "detail": match.detail}
                for match in hash_matches
                if match.url.endswith(report.sha256)
            ),
            {"matched": False},
        )
        attachment_layers.append(payload)

    url_flagged = len(intel.matches) + sum(
        1 for item in findings if item.code in {"lookalike", "link_mismatch"} and item.polarity == "risk"
    )
    checks = build_checks(
        flags,
        url_count=len(combined_urls),
        url_flagged=url_flagged,
        attachment_reports=attachment_layers,
        attachment_names=email.attachment_names,
        wording_severe=flags.severe_text,
        wording_credential=flags.semantic_phish and not flags.severe_text,
    )

    return AnalysisResponse(
        message_id=email.message_id,
        score=decision.score,
        verdict=decision.verdict,
        color=color_for(decision.verdict),
        summary=decision.summary,
        reasons=public_reasons(decision.findings),
        checks=checks,
        mitigations=mitigations_for(
            decision.verdict,
            file_active=flags.file_active,
            credential_ask=flags.semantic_phish and not flags.severe_text,
        ),
        suggested_actions=suggested_actions(decision.verdict),
        layers={
            "authentication": {
                "spf": auth.spf,
                "dkim": auth.dkim,
                "dmarc": auth.dmarc,
                "source": auth.source,
                "dns": published,
            },
            "identity": {
                "spoofing_detected": spoof.spoofing_detected,
                "risk_weight": spoof.risk_weight,
                "matched_brand": spoof.matched_brand,
                "sender_domain": sender,
                "is_new_domain": age.is_new_domain,
                "sender_domain_age_days": age.age_days,
            },
            "urls": {
                "extracted": combined_urls,
                "matches": [match.model_dump() for match in [*intel.matches, *hash_matches]],
                "unavailable": list(dict.fromkeys([*intel.unavailable, *hash_unavailable])),
                "lookalikes": [item.text for item in findings if item.code == "lookalike"],
            },
            "attachments": attachment_layers,
            "text": text.model_dump(),
            "meta": {
                "engine": engine,
                "band": decision.band,
                "raw_score": capped_raw(findings),
                "analyst": decision.analyst,
            },
        },
    )


async def _sender_age(sender: str):
    created = None
    if sender and domain_age.whois_available():
        created = await asyncio.to_thread(domain_age.lookup_creation_date, sender)
    return domain_age.assess_domain_age(created, domain=sender)


async def _url_domain_ages(urls: list[str], sender: str) -> list[Finding]:
    from app.brands import host_of

    sender_reg = registrable_domain(sender) if sender else ""
    hosts: list[str] = []
    for url in urls:
        host = host_of(url)
        registrable = registrable_domain(host) if host else ""
        if registrable and registrable != sender_reg and registrable not in hosts:
            hosts.append(registrable)
        if len(hosts) >= 3:
            break
    findings: list[Finding] = []
    for host in hosts:
        created = await asyncio.to_thread(domain_age.lookup_creation_date, host)
        age = domain_age.assess_domain_age(created, domain=host)
        if age.is_new_domain and age.reason:
            findings.append(
                Finding(
                    layer="url",
                    code="new_link_domain",
                    polarity="risk",
                    text=age.reason,
                    points=age.points,
                )
            )
    return findings


async def _screen(urls: list[str], *, client, url_screen) -> tuple[UrlIntelReport, bool]:
    screen = url_screen or url_intel.screen_urls
    try:
        report = await screen(urls, client=client)
    except TypeError:
        try:
            report = await screen(urls)
        except Exception:
            logger.exception("URL intelligence failed")
            return UrlIntelReport(checked=list(urls), unavailable=["urlhaus_error"]), True
    except Exception:
        logger.exception("URL intelligence failed")
        return UrlIntelReport(checked=list(urls), unavailable=["urlhaus_error"]), True
    if not isinstance(report, UrlIntelReport):
        return UrlIntelReport(checked=list(urls), unavailable=["urlhaus_error"]), True
    return report, False


async def _hash_screen(
    hashes: list[str],
    *,
    client,
    hash_lookup,
) -> tuple[list[UrlMatch], list[str]]:
    lookup = hash_lookup or hash_intel.lookup_hashes
    try:
        matches, unavailable = await lookup(hashes, client=client)
    except TypeError:
        try:
            matches, unavailable = await lookup(hashes)
        except Exception:
            logger.exception("Hash intelligence failed")
            return [], ["malwarebazaar_error"]
    except Exception:
        logger.exception("Hash intelligence failed")
        return [], ["malwarebazaar_error"]
    if not isinstance(matches, list):
        return [], ["malwarebazaar_error"]
    return matches, list(unavailable or [])


async def _published_dns(sender: str) -> dict:
    from app.config import get_settings

    if not sender or not get_settings().enable_live_dns:
        return {}
    return await asyncio.to_thread(authentication.lookup_published_records, sender)


def _merge_urls(*groups: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for url in group:
            key = url.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            merged.append(url.strip())
            if len(merged) >= 20:
                return merged
    return merged


