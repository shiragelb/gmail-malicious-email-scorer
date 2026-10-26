"""Dangerous attachment names."""

from __future__ import annotations

from app.schemas import Finding

DANGEROUS_SUFFIXES = (
    ".exe",
    ".scr",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".iso",
    ".img",
    ".lnk",
    ".bat",
    ".cmd",
    ".ps1",
    ".jar",
    ".msi",
    ".html",
    ".htm",
    ".svg",
    ".hta",
    ".wsf",
)


def assess(names: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for name in names:
        lowered = (name or "").lower().strip()
        if not lowered:
            continue
        if lowered.endswith(DANGEROUS_SUFFIXES):
            findings.append(
                Finding(
                    layer="identity",
                    code="dangerous_attachment",
                    polarity="risk",
                    text=f"The attachment {name} uses a file type commonly used to deliver malware.",
                    points=16,
                )
            )
    return findings
