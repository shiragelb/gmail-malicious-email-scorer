"""Request and response models shared by the API and the analysis layers."""

from __future__ import annotations

import base64
from email.utils import parseaddr
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Verdict = Literal["Safe", "Suspicious", "Malicious"]
Polarity = Literal["risk", "trust", "note"]
RiskWeight = Literal["none", "low", "high", "unknown"]

MAX_ATTACHMENTS = 5
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024
MAX_ATTACHMENT_TOTAL_BYTES = 10 * 1024 * 1024
SUPPORTED_SCHEMA_VERSIONS = frozenset({1, 2})


def _estimated_decoded_size(content_b64: str) -> int:
    return len(content_b64) * 3 // 4


class AttachmentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = ""
    content_type: str = ""
    size: int = 0
    content_b64: str = ""

    @model_validator(mode="after")
    def _trim_and_check(self) -> "AttachmentInput":
        self.name = (self.name or "")[:300]
        self.content_type = (self.content_type or "")[:200]
        if self.size < 0:
            self.size = 0
        if self.content_b64:
            # Reject oversized payloads before allocating the decoded bytes.
            if _estimated_decoded_size(self.content_b64) > MAX_ATTACHMENT_BYTES + 3:
                raise ValueError(f"An attachment exceeds the {MAX_ATTACHMENT_BYTES} byte limit.")
            try:
                raw = base64.b64decode(self.content_b64, validate=False)
            except Exception as exc:
                raise ValueError("An attachment is not valid base64.") from exc
            if len(raw) > MAX_ATTACHMENT_BYTES:
                raise ValueError(f"An attachment exceeds the {MAX_ATTACHMENT_BYTES} byte limit.")
            if self.size <= 0:
                self.size = len(raw)
        else:
            self.content_b64 = ""
        return self

    def decoded_bytes(self) -> bytes | None:
        if not self.content_b64:
            return None
        try:
            return base64.b64decode(self.content_b64, validate=False)
        except Exception:
            return None


class EmailInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    message_id: str | None = None
    subject: str = ""
    from_display: str = ""
    from_address: str = ""
    from_raw: str = ""
    reply_to: str = ""
    body_text: str = ""
    body_html: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    attachment_names: list[str] = Field(default_factory=list)
    attachments: list[AttachmentInput] = Field(default_factory=list)

    @field_validator("headers", mode="before")
    @classmethod
    def _trim_headers(cls, value: dict[str, str] | None) -> dict[str, str]:
        if not value:
            return {}
        trimmed: dict[str, str] = {}
        for key, item in list(value.items())[:40]:
            trimmed[str(key)[:200]] = str(item)[:20_000]
        return trimmed

    @field_validator("attachment_names", mode="before")
    @classmethod
    def _none_attachments(cls, value: list[str] | None) -> list[str]:
        return value or []

    @field_validator("attachments", mode="before")
    @classmethod
    def _none_attachment_objects(cls, value: list | None) -> list:
        return value or []

    @model_validator(mode="after")
    def _fill_and_limit(self) -> "EmailInput":
        if self.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError("Unsupported payload schema_version. Update the add-on.")
        if self.message_id:
            self.message_id = self.message_id[:200]
        if self.from_raw and not self.from_address:
            name, address = parseaddr(self.from_raw)
            if not self.from_display:
                self.from_display = name
            self.from_address = address
        self.subject = self.subject[:998]
        self.from_display = self.from_display[:500]
        self.from_address = self.from_address[:320].strip()
        self.reply_to = self.reply_to[:320].strip()
        self.body_text = self.body_text[:80_000]
        self.body_html = self.body_html[:80_000]
        self.attachment_names = [name[:300] for name in self.attachment_names[:50]]
        if len(self.attachments) > MAX_ATTACHMENTS:
            raise ValueError(f"At most {MAX_ATTACHMENTS} attachments with content are accepted.")
        total = sum(_estimated_decoded_size(item.content_b64) for item in self.attachments)
        if total > MAX_ATTACHMENT_TOTAL_BYTES + 3 * len(self.attachments):
            raise ValueError(
                f"Attachment payload exceeds the {MAX_ATTACHMENT_TOTAL_BYTES} byte total limit."
            )
        names = list(self.attachment_names)
        for item in self.attachments:
            if item.name and item.name not in names:
                names.append(item.name)
        self.attachment_names = names[:50]
        return self


class Finding(BaseModel):
    layer: str
    code: str
    polarity: Polarity
    text: str
    points: int = 0


class Reason(BaseModel):
    polarity: Polarity
    text: str
    layer: str


class SpoofAssessment(BaseModel):
    spoofing_detected: bool
    risk_weight: RiskWeight
    points: int
    reason: str
    matched_brand: str | None = None


class DomainAgeAssessment(BaseModel):
    domain: str
    is_new_domain: bool
    age_days: int | None = None
    risk_weight: RiskWeight
    points: int
    reason: str


class AuthAssessment(BaseModel):
    spf: str
    dkim: str
    dmarc: str
    source: str
    findings: list[Finding]


class TextAssessment(BaseModel):
    phishing_probability: float
    is_phishing: bool
    is_severe: bool = False
    points: int
    indicators: list[str]
    model: str
    transformer_probability: float | None = None


class UrlMatch(BaseModel):
    url: str
    provider: str
    threat: str
    detail: str
    points: int
    confirmed: bool = True


class UrlIntelReport(BaseModel):
    matches: list[UrlMatch] = Field(default_factory=list)
    unavailable: list[str] = Field(default_factory=list)
    checked: list[str] = Field(default_factory=list)

    @property
    def matched(self) -> bool:
        return any(match.confirmed for match in self.matches)

    @property
    def penalty_points(self) -> int:
        return sum(match.points for match in self.matches)


class AgentSafety(BaseModel):
    """Machine-readable guidance for any AI agent that reads the same mailbox."""

    prompt_injection: bool = False
    hidden_instructions: bool = False
    categories: list[str] = Field(default_factory=list)
    do_not_act: bool = False
    do_not_summarize_verbatim: bool = False


class CheckItem(BaseModel):
    """One row on the sidebar checklist: what was inspected and how it went."""

    id: str
    label: str
    detail: str = ""
    status: Literal["pass", "warn", "fail", "skip"] = "pass"


class AnalysisResponse(BaseModel):
    message_id: str | None = None
    score: int
    verdict: Verdict
    color: Literal["green", "amber", "red"]
    summary: str
    reasons: list[Reason]
    checks: list[CheckItem] = Field(default_factory=list)
    mitigations: list[str]
    suggested_actions: list[str]
    agent_safety: AgentSafety = Field(default_factory=AgentSafety)
    layers: dict
