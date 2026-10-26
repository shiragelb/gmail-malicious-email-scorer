"""Print the three QA scenarios and exit non-zero if a score falls outside its range."""

from __future__ import annotations

import asyncio
import sys

from app.pipeline import analyze_email
from app.scenarios import SCENARIOS
from app.layers.url_intel import reserved_url_matches
from app.schemas import UrlIntelReport


async def _offline_screen(urls: list[str], **kwargs) -> UrlIntelReport:
    del kwargs
    return UrlIntelReport(matches=reserved_url_matches(urls), checked=list(urls))


async def run() -> int:
    failed = 0
    for scenario in SCENARIOS:
        result = await analyze_email(scenario.email, url_screen=_offline_screen)
        ok = (
            scenario.expected_min <= result.score <= scenario.expected_max
            and result.verdict == scenario.expected_verdict
        )
        status = "OK" if ok else "FAIL"
        print(f"{scenario.id} {result.score:>3}/100  {result.verdict:<11} {status}  {result.summary}")
        for reason in result.reasons:
            print(f"    - {reason.text}")
        if not ok:
            failed += 1
            print(f"    expected {scenario.expected_verdict} {scenario.expected_min}-{scenario.expected_max}")
    return failed


def main() -> None:
    sys.exit(asyncio.run(run()))


if __name__ == "__main__":
    main()
