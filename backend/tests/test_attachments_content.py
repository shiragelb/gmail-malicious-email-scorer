"""Attachment content inspection and MalwareBazaar hash matching."""

from __future__ import annotations

import base64
import io
import zipfile

import pytest

from app.layers.file_inspect import detect_type, inspect_attachments
from app.pipeline import analyze_email
from app.schemas import AttachmentInput, EmailInput, UrlMatch
from app.scoring import ScoreDecision, apply_guardrails


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _attachment(name: str, raw: bytes, content_type: str = "application/octet-stream") -> AttachmentInput:
    return AttachmentInput(name=name, content_type=content_type, size=len(raw), content_b64=_b64(raw))


def _pdf_with_open_action() -> bytes:
    return b"""%PDF-1.4
1 0 obj<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\\(1\\);) >> >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>endobj
4 0 obj<< /Length 44 >>stream
BT /F1 12 Tf 100 100 Td (hello) Tj ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000114 00000 n 
0000000171 00000 n 
0000000260 00000 n 
trailer<< /Size 5 /Root 1 0 R >>
startxref
354
%%EOF
"""


def _pdf_with_phish_text() -> bytes:
    body = (
        "BT /F1 12 Tf 40 700 Td "
        "(Verify your password immediately at https://paypa1-secure.com/login) Tj ET"
    )
    stream = body.encode("latin-1")
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n"
        b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n"
        b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>endobj\n"
        + f"4 0 obj<< /Length {len(stream)} >>stream\n".encode()
        + stream
        + b"\nendstream\nendobj\n"
        b"trailer<< /Root 1 0 R >>\n%%EOF\n"
    )


def _plain_pdf() -> bytes:
    return b"""%PDF-1.4
1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>endobj
trailer<< /Root 1 0 R >>
%%EOF
"""


def _zip_with_member(name: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


def _xlsm_with_vba() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types></Types>")
        archive.writestr("xl/workbook.xml", "<workbook></workbook>")
        archive.writestr("xl/vbaProject.bin", b"fake-vba-project")
    return buffer.getvalue()


def _plain_xlsx() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types></Types>")
        archive.writestr("xl/workbook.xml", "<workbook></workbook>")
        archive.writestr("xl/sharedStrings.xml", "<sst><si><t>Quarterly report</t></si></sst>")
    return buffer.getvalue()


def _xlsx_with_innocent_added() -> bytes:
    """Contains the substring 'dde' inside 'added' — must not trip office_dde."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types></Types>")
        archive.writestr("xl/workbook.xml", "<workbook></workbook>")
        archive.writestr(
            "xl/sharedStrings.xml",
            "<sst><si><t>Rows added for charities and address list</t></si></sst>",
        )
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            "<worksheet><sheetData><row><c><v>1</v></c></row></sheetData></worksheet>",
        )
    return buffer.getvalue()


def _xlsx_with_dde_formula() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types></Types>")
        archive.writestr("xl/workbook.xml", "<workbook></workbook>")
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            '<worksheet><sheetData><row><c t="str"><f>=DDE("cmd","/c calc","")</f></c></row></sheetData></worksheet>',
        )
    return buffer.getvalue()


def _xlsx_with_cmd_pipe() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types></Types>")
        archive.writestr("xl/workbook.xml", "<workbook></workbook>")
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            "<worksheet><sheetData><row><c><f>=CMD|'/c notepad'!A0</f></c></row></sheetData></worksheet>",
        )
    return buffer.getvalue()


def _zip_bomb() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("zeros.bin")
        # Store a small compressed payload while advertising a huge size via ZipInfo
        # by writing compressible zeros; inspection should stop on ratio/size budget.
        archive.writestr(info, b"\x00" * 2_000_000)
    return buffer.getvalue()


@pytest.mark.asyncio
async def test_pdf_open_action_is_suspicious_attachment_band():
    email = EmailInput(
        subject="Invoice",
        from_display="Billing",
        from_address="billing@contoso.com",
        body_text="Please see the attached invoice.",
        attachments=[_attachment("invoice.pdf", _pdf_with_open_action(), "application/pdf")],
    )
    result = await analyze_email(email)
    assert result.layers["meta"]["band"] == "attachment"
    assert result.verdict == "Suspicious"
    assert 60 <= result.score <= 80
    assert any(item["active"] for item in result.layers["attachments"])


@pytest.mark.asyncio
async def test_pdf_phishing_text_is_suspicious():
    email = EmailInput(
        subject="Account",
        from_display="Support",
        from_address="support@example.com",
        body_text="See the attachment.",
        attachments=[_attachment("notice.pdf", _pdf_with_phish_text(), "application/pdf")],
    )
    result = await analyze_email(email)
    assert result.verdict == "Suspicious"
    assert result.score >= 48
    blob = " ".join(reason.text for reason in result.reasons).lower()
    assert "password" in blob or "attachment" in blob


@pytest.mark.asyncio
async def test_xlsm_with_vba_is_flagged():
    report = inspect_attachments([_attachment("sheet.xlsm", _xlsm_with_vba())])
    assert report.active
    assert any(item.code == "office_macro" for item in report.findings)


def test_xlsx_with_word_added_is_not_dde():
    report = inspect_attachments([_attachment("charities.xlsx", _xlsx_with_innocent_added())])
    assert not any(item.code == "office_dde" for item in report.findings)
    assert report.active is False


def test_xlsx_dde_formula_is_flagged():
    report = inspect_attachments([_attachment("payload.xlsx", _xlsx_with_dde_formula())])
    assert report.active
    assert any(item.code == "office_dde" for item in report.findings)


def test_xlsx_cmd_pipe_formula_is_flagged():
    report = inspect_attachments([_attachment("payload.xlsx", _xlsx_with_cmd_pipe())])
    assert report.active
    assert any(item.code == "office_dde" for item in report.findings)


@pytest.mark.asyncio
async def test_disguised_executable_named_pdf():
    raw = b"MZ" + b"\x00" * 120
    email = EmailInput(
        subject="Invoice",
        from_display="Billing",
        from_address="billing@example.com",
        body_text="Attached.",
        attachments=[_attachment("invoice.pdf", raw)],
    )
    result = await analyze_email(email)
    assert result.layers["meta"]["band"] == "attachment"
    assert result.verdict == "Suspicious"
    assert any("disguised" in reason.text.lower() or "executable" in reason.text.lower() for reason in result.reasons)


@pytest.mark.asyncio
async def test_zip_with_inner_exe_is_flagged():
    raw = _zip_with_member("invoice.exe", b"MZ" + b"\x00" * 40)
    report = inspect_attachments([_attachment("docs.zip", raw)])
    assert any(item.code == "archive_executable" for item in report.findings)
    email = EmailInput(
        subject="Docs",
        from_display="Office",
        from_address="office@example.com",
        body_text="Files attached.",
        attachments=[_attachment("docs.zip", raw)],
    )
    result = await analyze_email(email)
    assert result.verdict == "Suspicious"
    assert result.layers["meta"]["band"] == "attachment"


def test_zip_bomb_does_not_crash():
    report = inspect_attachments([_attachment("bomb.zip", _zip_bomb())])
    assert report.reports
    assert report.reports[0].detected_type in {"zip", "office_zip"}


@pytest.mark.asyncio
async def test_plain_pdf_and_xlsx_stay_safe():
    email = EmailInput(
        subject="Q3 report",
        from_display="Finance",
        from_address="finance@contoso.com",
        body_text="The report is attached.",
        headers={
            "Authentication-Results": (
                "mx.google.com; spf=pass smtp.mailfrom=finance@contoso.com; "
                "dkim=pass header.i=@contoso.com; dmarc=pass header.from=contoso.com"
            )
        },
        attachments=[
            _attachment("notes.pdf", _plain_pdf(), "application/pdf"),
            _attachment("report.xlsx", _plain_xlsx(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ],
    )
    result = await analyze_email(email)
    assert result.verdict == "Safe"
    assert result.score <= 15


@pytest.mark.asyncio
async def test_malwarebazaar_hash_hit_is_malicious():
    raw = _plain_pdf()
    email = EmailInput(
        subject="Invoice",
        from_display="Billing",
        from_address="billing@example.com",
        body_text="See attached.",
        attachments=[_attachment("invoice.pdf", raw, "application/pdf")],
    )

    async def fake_hash(hashes, **kwargs):
        del kwargs
        digest = hashes[0]
        return (
            [
                UrlMatch(
                    url=f"sha256:{digest}",
                    provider="malwarebazaar",
                    threat="emotet",
                    detail=f"MalwareBazaar lists the attachment hash {digest[:12]}… as Emotet.",
                    points=35,
                    confirmed=True,
                )
            ],
            [],
        )

    result = await analyze_email(email, hash_lookup=fake_hash)
    assert result.verdict == "Malicious"
    assert result.score >= 90
    assert result.layers["meta"]["band"] == "confirmed"


def test_attachment_guardrail_keeps_claude_in_band():
    local = ScoreDecision(score=60, verdict="Suspicious", band="attachment", summary="Active file.")
    assert apply_guardrails(local, 99) == 80
    assert apply_guardrails(local, 10) == 60


def test_detect_type_from_bytes_not_name():
    assert detect_type(b"%PDF-1.4", "note.txt") == "pdf"
    assert detect_type(b"MZ\x90\x00", "invoice.pdf") == "pe"
    assert detect_type(b"PK\x03\x04", "sheet.xlsm") == "office_zip"
