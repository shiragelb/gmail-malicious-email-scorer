"""SPF, DKIM, and DMARC results taken from the message headers Gmail already recorded."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from app.config import get_settings
from app.schemas import AuthAssessment, Finding

# #region agent log
_DEBUG_LOG = Path(__file__).resolve().parents[3] / "debug-9947bd.log"


def _dbg(hypothesis_id: str, location: str, message: str, data: dict) -> None:
    try:
        payload = {
            "sessionId": "9947bd",
            "runId": "pre-fix",
            "hypothesisId": hypothesis_id,
            "location": location,
            "message": message,
            "data": data,
            "timestamp": int(time.time() * 1000),
        }
        with _DEBUG_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
    except Exception:
        pass


# #endregion

_RESULT_RE = {
    "spf": re.compile(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE),
    "dkim": re.compile(r"\bdkim=(pass|fail|none|neutral|policy|temperror|permerror)\b", re.IGNORECASE),
    "dmarc": re.compile(r"\bdmarc=(pass|fail|none|bestguesspass|neutral|temperror|permerror)\b", re.IGNORECASE),
}
_RECEIVED_SPF_RE = re.compile(
    r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)

_FAIL_POINTS = {"spf": 18, "dkim": 10, "dmarc": 10}
_SOFT_POINTS = {"spf": 10, "dkim": 0, "dmarc": 0}


def _header(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower() and value:
            return value
    return ""


def _first(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text or "")
    if not match:
        return None
    return match.group(1).lower()


def assess(headers: dict[str, str] | None) -> AuthAssessment:
    headers = headers or {}
    auth_text = "\n".join(
        part
        for part in (
            _header(headers, "Authentication-Results"),
            _header(headers, "ARC-Authentication-Results"),
        )
        if part
    )
    source = "header" if auth_text or _header(headers, "Received-SPF") else "none"
    spf = _first(_RESULT_RE["spf"], auth_text)
    dkim = _first(_RESULT_RE["dkim"], auth_text) or "unknown"
    dmarc = _first(_RESULT_RE["dmarc"], auth_text) or "unknown"
    if spf is None:
        received = _first(_RECEIVED_SPF_RE, _header(headers, "Received-SPF"))
        spf = received or "unknown"
    if spf == "bestguesspass":
        spf = "pass"

    # #region agent log
    auth_raw = _header(headers, "Authentication-Results")
    arc_raw = _header(headers, "ARC-Authentication-Results")
    received_raw = _header(headers, "Received-SPF")
    _dbg(
        "A",
        "authentication.py:assess",
        "auth header presence",
        {
            "header_keys": sorted(str(k) for k in headers.keys()),
            "header_count": len(headers),
            "has_auth_results": bool(auth_raw),
            "has_arc": bool(arc_raw),
            "has_received_spf": bool(received_raw),
            "auth_results_len": len(auth_raw),
            "arc_len": len(arc_raw),
            "received_spf_len": len(received_raw),
            "auth_snippet": (auth_raw or arc_raw or received_raw)[:180],
        },
    )
    _dbg(
        "C",
        "authentication.py:assess",
        "parsed auth results",
        {
            "source": source,
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "all_pass": spf == "pass" and dkim == "pass" and dmarc == "pass",
        },
    )
    # #endregion

    findings: list[Finding] = []
    if spf == "pass" and dkim == "pass" and dmarc == "pass":
        findings.append(
            Finding(
                layer="authentication",
                code="auth_pass",
                polarity="trust",
                text="SPF, DKIM, and DMARC passed.",
                points=0,
            )
        )
    else:
        for name, result in (("spf", spf), ("dkim", dkim), ("dmarc", dmarc)):
            label = name.upper()
            if result == "fail":
                findings.append(
                    Finding(
                        layer="authentication",
                        code=f"{name}_fail",
                        polarity="risk",
                        text=f"{label} failed for this message.",
                        points=_FAIL_POINTS[name],
                    )
                )
            elif result == "softfail" and _SOFT_POINTS[name]:
                findings.append(
                    Finding(
                        layer="authentication",
                        code=f"{name}_softfail",
                        polarity="risk",
                        text=f"{label} soft-failed for this message.",
                        points=_SOFT_POINTS[name],
                    )
                )
            elif result == "pass":
                findings.append(
                    Finding(
                        layer="authentication",
                        code=f"{name}_pass",
                        polarity="trust",
                        text=f"{label} passed.",
                        points=0,
                    )
                )

    if source == "none":
        findings.append(
            Finding(
                layer="authentication",
                code="auth_missing",
                polarity="note",
                text="No SPF, DKIM, or DMARC result was included with this message, so authentication was not scored as a failure.",
                points=0,
            )
        )

    return AuthAssessment(spf=spf, dkim=dkim, dmarc=dmarc, source=source, findings=findings)


def lookup_published_records(domain: str) -> dict[str, str]:
    """Optional dnspython check that the domain publishes SPF and DMARC. This does not re-score the received message."""
    if not domain or not get_settings().enable_live_dns:
        return {}
    try:
        import dns.resolver
    except ImportError:
        return {}

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    published: dict[str, str] = {}
    try:
        answers = resolver.resolve(domain, "TXT")
        for answer in answers:
            text = "".join(part.decode() if isinstance(part, bytes) else str(part) for part in answer.strings)
            if text.lower().startswith("v=spf1"):
                published["spf"] = "published"
                break
    except Exception:
        published["spf"] = "lookup_failed"
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for answer in answers:
            text = "".join(part.decode() if isinstance(part, bytes) else str(part) for part in answer.strings)
            if "v=dmarc1" in text.lower():
                published["dmarc"] = "published"
                break
    except Exception:
        published["dmarc"] = "lookup_failed"
    return published
