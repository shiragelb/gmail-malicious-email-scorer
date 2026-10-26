"""Write tiny synthetic Office files used by the attack eval suite. Not malware."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent / "fixtures"


def _xlsx(parts: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types></Types>")
        archive.writestr("xl/workbook.xml", "<workbook></workbook>")
        for name, data in parts.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def main() -> None:
    HERE.mkdir(parents=True, exist_ok=True)
    (HERE / "benign.xlsx").write_bytes(
        _xlsx(
            {
                "xl/sharedStrings.xml": "<sst><si><t>Rows added for charities and address list</t></si></sst>",
                "xl/worksheets/sheet1.xml": "<worksheet><sheetData><row><c><v>1</v></c></row></sheetData></worksheet>",
            }
        )
    )
    (HERE / "dde.xlsx").write_bytes(
        _xlsx(
            {
                "xl/worksheets/sheet1.xml": (
                    '<worksheet><sheetData><row><c t="str">'
                    '<f>=DDE("cmd","/c calc","")</f></c></row></sheetData></worksheet>'
                )
            }
        )
    )
    (HERE / "cmd.xlsx").write_bytes(
        _xlsx(
            {
                "xl/worksheets/sheet1.xml": (
                    "<worksheet><sheetData><row><c>"
                    "<f>=CMD|'/c notepad'!A0</f></c></row></sheetData></worksheet>"
                )
            }
        )
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types></Types>")
        archive.writestr("xl/workbook.xml", "<workbook></workbook>")
        archive.writestr("xl/vbaProject.bin", b"fake-vba-project")
    (HERE / "macro.xlsm").write_bytes(buffer.getvalue())
    print(f"wrote fixtures in {HERE}")


if __name__ == "__main__":
    main()
