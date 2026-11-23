"""Real metadata sanitization for uploaded PDF and DOCX files."""

from __future__ import annotations

import re
import zipfile
from io import BytesIO
from pathlib import Path

ALLOWED_EXTENSIONS = {".pdf", ".docx"}
MIME_TYPES = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


def sanitize_document(filename: str, data: bytes) -> tuple[bytes, str, str]:
    extension = Path(filename).suffix.casefold()
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Only PDF and DOCX files can be sanitized.")
    if not data:
        raise ValueError("The uploaded file is empty.")

    stem = Path(filename).stem[:180] or "document"
    output_name = f"{stem}-clean{extension}"

    if extension == ".pdf":
        import fitz

        with fitz.open(stream=data, filetype="pdf") as document:
            document.set_metadata({})
            document.del_xml_metadata()
            for name in document.embfile_names():
                document.embfile_del(name)
            cleaned = document.tobytes(garbage=4, deflate=True)
        return cleaned, output_name, MIME_TYPES[extension]

    from docx import Document

    document = Document(BytesIO(data))
    core = document.core_properties
    for field in (
        "author", "last_modified_by", "title", "subject", "keywords", "comments",
        "category", "identifier", "language", "content_status", "version",
    ):
        if hasattr(core, field):
            setattr(core, field, "")
    core.revision = 1

    staged = BytesIO()
    document.save(staged)

    output = BytesIO()
    with zipfile.ZipFile(BytesIO(staged.getvalue())) as source, zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as target:
        for item in source.infolist():
            if item.filename == "docProps/custom.xml":
                continue
            payload = source.read(item.filename)
            if item.filename.casefold() == "docprops/app.xml":
                text = payload.decode("utf-8", errors="replace")
                text = re.sub(r"<Company>.*?</Company>", "<Company></Company>", text, flags=re.IGNORECASE | re.DOTALL)
                text = re.sub(r"<Manager>.*?</Manager>", "<Manager></Manager>", text, flags=re.IGNORECASE | re.DOTALL)
                payload = text.encode("utf-8")
            target.writestr(item, payload)

    return output.getvalue(), output_name, MIME_TYPES[extension]
