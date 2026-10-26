"""In-memory inspection of PDF, Office, and archive attachments. Files are never executed."""

from __future__ import annotations

import io
import logging
import re
import time
import zipfile
from dataclasses import dataclass, field
from typing import Iterable

from app.schemas import AttachmentInput, Finding

logger = logging.getLogger(__name__)

MAX_TEXT_CHARS = 20_000
MAX_ZIP_MEMBERS = 40
MAX_UNCOMPRESSED_BYTES = 30 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
PER_FILE_BUDGET_SECONDS = 4.0

_DANGEROUS_INNER = (
    ".exe",
    ".scr",
    ".dll",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".bat",
    ".cmd",
    ".ps1",
    ".jar",
    ".msi",
    ".lnk",
    ".hta",
    ".wsf",
    ".iso",
    ".img",
    ".html",
    ".htm",
)

_ACTIVE_CODES = {
    "pdf_javascript",
    "pdf_open_action",
    "pdf_launch",
    "pdf_embedded_file",
    "office_macro",
    "office_auto_macro",
    "office_risky_macro",
    "office_embedded_ole",
    "office_dde",
    "archive_executable",
    "disguised_executable",
}

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_URI_RE = re.compile(r"/URI\s*\(([^)]+)\)", re.IGNORECASE)
_PDF_JS_RE = re.compile(r"/(?:JavaScript|JS)\b", re.IGNORECASE)
_PDF_OPEN_RE = re.compile(r"/(?:OpenAction|AA)\b", re.IGNORECASE)
_PDF_LAUNCH_RE = re.compile(r"/Launch\b", re.IGNORECASE)
_PDF_EMBED_RE = re.compile(r"/EmbeddedFile\b", re.IGNORECASE)

# Real DDE / command-formula patterns — not the substring "dde" (false-positives on "added").
_OFFICE_DDE_RE = re.compile(
    r"(?:"
    r"=\s*DDE(?:AUTO)?\s*\("  # Excel =DDE( / =DDEAUTO(
    r"|\bDDE(?:AUTO)?\s*\("  # DDE( / DDEAUTO( in formulas or fields
    r"|=\s*CMD\s*\|"  # Classic =CMD|'/c ...' Excel formula
    r"|CMD\s*\|\s*['\"]?/?\s*c\b"  # CMD|/c or CMD|'/c
    r"|=\s*MSEXCEL\s*\|"  # =MSEXCEL|...
    r"|\bddeLink\b"  # OOXML ddeLink element / relationship
    r"|Target\s*=\s*[\"']DDE[\"']"  # relationship target DDE
    r")",
    re.IGNORECASE,
)


@dataclass
class FileReport:
    name: str
    detected_type: str = "unknown"
    sha256: str = ""
    size: int = 0
    findings: list[Finding] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    text: str = ""
    active: bool = False
    skipped_reason: str = ""

    def to_layer_dict(self) -> dict:
        return {
            "name": self.name,
            "detected_type": self.detected_type,
            "sha256": self.sha256,
            "size": self.size,
            "active": self.active,
            "skipped_reason": self.skipped_reason,
            "urls": list(self.urls),
            "findings": [item.model_dump() for item in self.findings],
        }


@dataclass
class FileInspectionResult:
    reports: list[FileReport] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        items: list[Finding] = []
        for report in self.reports:
            items.extend(report.findings)
        return items

    @property
    def urls(self) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for report in self.reports:
            for url in report.urls:
                key = url.strip().lower()
                if not key or key in seen:
                    continue
                seen.add(key)
                found.append(url.strip())
        return found

    @property
    def text(self) -> str:
        parts = [report.text for report in self.reports if report.text]
        return "\n".join(parts)[:MAX_TEXT_CHARS]

    @property
    def active(self) -> bool:
        return any(report.active for report in self.reports)


def inspect_attachments(attachments: Iterable[AttachmentInput]) -> FileInspectionResult:
    result = FileInspectionResult()
    for item in attachments:
        result.reports.append(_inspect_one(item))
    return result


def _inspect_one(item: AttachmentInput) -> FileReport:
    import hashlib

    report = FileReport(name=item.name or "attachment", size=item.size)
    raw = item.decoded_bytes()
    if raw is None:
        report.skipped_reason = "no_content"
        return report
    report.size = len(raw)
    report.sha256 = hashlib.sha256(raw).hexdigest()
    report.detected_type = detect_type(raw, item.name)

    started = time.monotonic()
    try:
        if report.detected_type == "pe":
            _flag_disguised(report, item.name)
        elif report.detected_type == "pdf":
            _inspect_pdf(report, raw)
        elif report.detected_type in {"zip", "office_zip"}:
            _inspect_zip_family(report, raw, item.name)
        elif report.detected_type == "ole":
            _inspect_ole(report, raw, item.name)
        else:
            report.findings.append(
                Finding(
                    layer="attachment",
                    code="unsupported_type",
                    polarity="note",
                    text=f"The attachment {report.name} was not a PDF, Office, or ZIP file the scorer inspects.",
                    points=0,
                )
            )
    except Exception as exc:
        logger.info("Attachment inspection failed for %s: %s", report.name, type(exc).__name__)
        report.findings.append(
            Finding(
                layer="attachment",
                code="inspect_failed",
                polarity="note",
                text=f"The attachment {report.name} could not be inspected. No penalty was added.",
                points=0,
            )
        )
    if time.monotonic() - started > PER_FILE_BUDGET_SECONDS:
        report.findings.append(
            Finding(
                layer="attachment",
                code="inspect_budget",
                polarity="note",
                text=f"Inspection of {report.name} hit the time budget. Partial findings may be incomplete.",
                points=0,
            )
        )
    report.active = any(item.code in _ACTIVE_CODES for item in report.findings)
    return report


def detect_type(raw: bytes, name: str = "") -> str:
    if raw.startswith(b"%PDF"):
        return "pdf"
    if raw.startswith(b"MZ"):
        return "pe"
    if raw.startswith(b"PK"):
        lowered = (name or "").lower()
        if lowered.endswith((".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm")):
            return "office_zip"
        return "zip"
    if raw.startswith(b"\xd0\xcf\x11\xe0"):
        return "ole"
    return "unknown"


def _flag_disguised(report: FileReport, name: str) -> None:
    lowered = (name or "").lower()
    if lowered.endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv")):
        report.findings.append(
            Finding(
                layer="attachment",
                code="disguised_executable",
                polarity="risk",
                text=f"The attachment {report.name} is a Windows executable disguised with a document name.",
                points=28,
            )
        )
    else:
        report.findings.append(
            Finding(
                layer="attachment",
                code="disguised_executable",
                polarity="risk",
                text=f"The attachment {report.name} is a Windows executable.",
                points=28,
            )
        )


def _inspect_pdf(report: FileReport, raw: bytes) -> None:
    sample = raw[: min(len(raw), 2_000_000)].decode("latin-1", errors="ignore")
    if _PDF_JS_RE.search(sample):
        report.findings.append(
            Finding(
                layer="attachment",
                code="pdf_javascript",
                polarity="risk",
                text=f"The PDF {report.name} contains JavaScript.",
                points=22,
            )
        )
    if _PDF_OPEN_RE.search(sample):
        report.findings.append(
            Finding(
                layer="attachment",
                code="pdf_open_action",
                polarity="risk",
                text=f"The PDF {report.name} has an automatic open action.",
                points=20,
            )
        )
    if _PDF_LAUNCH_RE.search(sample):
        report.findings.append(
            Finding(
                layer="attachment",
                code="pdf_launch",
                polarity="risk",
                text=f"The PDF {report.name} can launch an external program.",
                points=24,
            )
        )
    if _PDF_EMBED_RE.search(sample):
        report.findings.append(
            Finding(
                layer="attachment",
                code="pdf_embedded_file",
                polarity="risk",
                text=f"The PDF {report.name} embeds another file.",
                points=18,
            )
        )
    for match in _URI_RE.findall(sample):
        url = match.strip().strip("<>").rstrip("\\")
        if url.lower().startswith(("http://", "https://")):
            report.urls.append(url)
    report.urls.extend(_URL_RE.findall(sample))
    report.urls = _dedupe_urls(report.urls)

    extracted = ""
    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(raw), strict=False)
        parts: list[str] = []
        for page in reader.pages[:20]:
            try:
                text = page.extract_text() or ""
            except Exception:
                text = ""
            if text:
                parts.append(text)
            if sum(len(part) for part in parts) >= MAX_TEXT_CHARS:
                break
        extracted = re.sub(r"\s+", " ", " ".join(parts)).strip()
    except Exception:
        extracted = ""
    # Prefer extracted page text; fall back to a sanitized raw sample so phishing
    # wording inside minimal PDF streams is still visible to the text layer.
    report.text = (extracted or re.sub(r"\s+", " ", sample))[:MAX_TEXT_CHARS]
    for match in _URL_RE.findall(report.text):
        report.urls.append(match)
    report.urls = _dedupe_urls(report.urls)


def _inspect_zip_family(report: FileReport, raw: bytes, name: str) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        report.findings.append(
            Finding(
                layer="attachment",
                code="inspect_failed",
                polarity="note",
                text=f"The attachment {report.name} looked like a ZIP archive but could not be opened.",
                points=0,
            )
        )
        return

    names = archive.namelist()[:MAX_ZIP_MEMBERS]
    if _is_encrypted_zip(archive):
        report.findings.append(
            Finding(
                layer="attachment",
                code="archive_encrypted",
                polarity="risk",
                text=f"The archive {report.name} is password-protected, which malware often uses to hide a payload.",
                points=14,
            )
        )

    total_uncompressed = 0
    has_vba = False
    has_ole = False
    sheet_parts: list[str] = []
    for info in archive.infolist()[:MAX_ZIP_MEMBERS]:
        total_uncompressed += max(info.file_size, 0)
        if info.file_size > 0 and info.compress_size > 0:
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > MAX_COMPRESSION_RATIO and info.file_size > 1_000_000:
                report.findings.append(
                    Finding(
                        layer="attachment",
                        code="inspect_failed",
                        polarity="note",
                        text=f"The archive {report.name} has an extreme compression ratio and was only partially inspected.",
                        points=0,
                    )
                )
                break
        if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
            report.findings.append(
                Finding(
                    layer="attachment",
                    code="inspect_failed",
                    polarity="note",
                    text=f"The archive {report.name} exceeds the uncompressed size budget and was only partially inspected.",
                    points=0,
                )
            )
            break
        lowered = info.filename.lower()
        if lowered.endswith("vbaproject.bin"):
            has_vba = True
        if "oleobject" in lowered or lowered.endswith(".bin") and "embeddings" in lowered:
            has_ole = True
        if any(lowered.endswith(suffix) for suffix in _DANGEROUS_INNER):
            report.findings.append(
                Finding(
                    layer="attachment",
                    code="archive_executable",
                    polarity="risk",
                    text=f"The archive {report.name} contains {info.filename}, a file type commonly used to deliver malware.",
                    points=24,
                )
            )
        if lowered.endswith((".rels", ".xml")) and info.file_size <= 500_000:
            try:
                data = archive.read(info.filename)
            except Exception:
                continue
            text = data.decode("utf-8", errors="ignore")
            if "TargetMode=\"External\"" in text or "TargetMode='External'" in text:
                for match in re.findall(r'Target="([^"]+)"', text):
                    if match.lower().startswith(("http://", "https://")):
                        report.urls.append(match)
            for match in _URL_RE.findall(text):
                report.urls.append(match)
            if _OFFICE_DDE_RE.search(text) and not any(
                item.code == "office_dde" for item in report.findings
            ):
                report.findings.append(
                    Finding(
                        layer="attachment",
                        code="office_dde",
                        polarity="risk",
                        text=f"The Office file {report.name} contains a DDE or command formula.",
                        points=22,
                    )
                )
            if lowered.endswith((".xml",)) and ("sheet" in lowered or "document" in lowered or "sharedstrings" in lowered):
                sheet_parts.append(re.sub(r"<[^>]+>", " ", text))

    if has_vba:
        report.findings.append(
            Finding(
                layer="attachment",
                code="office_macro",
                polarity="risk",
                text=f"The Office file {report.name} contains a VBA macro project.",
                points=20,
            )
        )
        _inspect_ole(report, raw, name)
    if has_ole:
        report.findings.append(
            Finding(
                layer="attachment",
                code="office_embedded_ole",
                polarity="risk",
                text=f"The Office file {report.name} embeds an OLE object.",
                points=18,
            )
        )

    report.text = re.sub(r"\s+", " ", " ".join(sheet_parts)).strip()[:MAX_TEXT_CHARS]
    report.urls = _dedupe_urls(report.urls)
    report.detected_type = "office_zip" if has_vba or (name or "").lower().endswith(
        (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm")
    ) else "zip"


def _inspect_ole(report: FileReport, raw: bytes, name: str) -> None:
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        report.findings.append(
            Finding(
                layer="attachment",
                code="inspect_failed",
                polarity="note",
                text=f"Macro inspection for {report.name} needs oletools, which is not installed.",
                points=0,
            )
        )
        return

    try:
        parser = VBA_Parser(filename=name or "attachment", data=raw)
    except Exception:
        return
    try:
        if not parser.detect_vba_macros():
            return
        if not any(item.code == "office_macro" for item in report.findings):
            report.findings.append(
                Finding(
                    layer="attachment",
                    code="office_macro",
                    polarity="risk",
                    text=f"The Office file {report.name} contains a VBA macro project.",
                    points=20,
                )
            )
        auto = False
        risky = False
        for _filename, _stream, _vba_filename, code in parser.extract_macros() or []:
            lowered = (code or "").lower()
            if any(token in lowered for token in ("autoopen", "workbook_open", "document_open", "auto_open", "autorun")):
                auto = True
            if any(
                token in lowered
                for token in ("shell(", "createobject(", "urldownloadtofile", "wscript.shell", "powershell")
            ):
                risky = True
            for match in _URL_RE.findall(code or ""):
                report.urls.append(match)
        if auto:
            report.findings.append(
                Finding(
                    layer="attachment",
                    code="office_auto_macro",
                    polarity="risk",
                    text=f"The Office file {report.name} has an auto-run macro entry point.",
                    points=24,
                )
            )
        if risky:
            report.findings.append(
                Finding(
                    layer="attachment",
                    code="office_risky_macro",
                    polarity="risk",
                    text=f"The Office file {report.name} macro code can launch programs or download files.",
                    points=26,
                )
            )
        report.urls = _dedupe_urls(report.urls)
    finally:
        try:
            parser.close()
        except Exception:
            pass


def _is_encrypted_zip(archive: zipfile.ZipFile) -> bool:
    for info in archive.infolist()[:MAX_ZIP_MEMBERS]:
        if info.flag_bits & 0x1:
            return True
    return False


def _dedupe_urls(urls: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for url in urls:
        key = url.strip().lower().rstrip(".,);]")
        if not key.startswith(("http://", "https://")) or key in seen:
            continue
        seen.add(key)
        unique.append(url.strip().rstrip(".,);]"))
        if len(unique) >= 20:
            break
    return unique
