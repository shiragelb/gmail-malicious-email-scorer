"""Display-name impersonation of well-known organizations."""

from __future__ import annotations

from app.brands import BRANDS, brand_for_domain, email_domain, mentions_brand
from app.schemas import SpoofAssessment


def detect_display_name_spoof(display_name: str, from_address: str) -> SpoofAssessment:
    domain = email_domain(from_address)
    if not (display_name or "").strip() or not domain:
        return SpoofAssessment(
            spoofing_detected=False,
            risk_weight="none",
            points=0,
            reason="",
        )

    for brand in BRANDS:
        if not mentions_brand(display_name, brand):
            continue
        if brand_for_domain(domain) == brand or any(
            domain == official or domain.endswith("." + official) for official in brand.domains
        ):
            continue
        return SpoofAssessment(
            spoofing_detected=True,
            risk_weight="high",
            points=24,
            matched_brand=brand.name,
            reason=(
                f"Display name claims {brand.name} but the sending domain is {domain}."
            ),
        )

    return SpoofAssessment(
        spoofing_detected=False,
        risk_weight="none",
        points=0,
        reason="",
    )
