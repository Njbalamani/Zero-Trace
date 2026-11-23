"""Document metadata extraction and sensitive-metadata detection."""

from __future__ import annotations

import re
import zipfile
from io import BytesIO
from xml.etree import ElementTree

from .text_detector import make_finding

SENSITIVE_CORE_FIELDS = {
    "author": "Author name",
    "lastmodby": "Last modified by",
    "last_modified_by": "Last modified by",
    "creator": "Creating application/user",
    "company": "Company",
    "manager": "Manager",
    "subject": "Subject",
    "keywords": "Keywords",
    "comments": "Comments",
    "category": "Category",
    "identifier": "Identifier",
}

XML_VALUE_RE = re.compile(r">([^<>]{2,200})<")


def _metadata_finding(field: str, value: str, tool: str) -> dict:
    label = SENSITIVE_CORE_FIELDS.get(field.casefold().replace(" ", ""), field)
    return make_finding(
        "metadata", "medium" if field.casefold() in {"author", "lastmodby", "last_modified_by", "company"} else "low",
        f"Sensitive document metadata: {label}",
        value,
        f"metadata:{field}",
        "Document metadata is copied when files are shared and can reveal internal users, systems, locations or project names even when visible content is clean.",
        "Use the document inspector/exif tool to remove author and custom properties before publishing, or export to a clean format.",
        source_tool=tool,
        confidence=0.9,
    )


def analyze_pdf(data: bytes) -> tuple[dict, list[dict], str]:
    try:
        import fitz  # PyMuPDF
    except ImportError as exc:  # pragma: no cover - environment guard
        raise RuntimeError("PyMuPDF is required for PDF scanning. Install backend requirements.") from exc

    with fitz.open(stream=data, filetype="pdf") as doc:
        raw = {str(key).lower(): str(value).strip() for key, value in (doc.metadata or {}).items() if value}
        info = {
            "page_count": doc.page_count,
            "encrypted": bool(doc.is_encrypted),
            "has_xmp": bool(doc.xref_xml_metadata()),
            "has_embedded_files": bool(doc.embfile_count()),
            "metadata_fields_present": sorted(raw.keys()),
        }
        findings = []
        for key, value in raw.items():
            if key in {"format", "encryption", "producer", "creator"} and len(value) < 40:
                continue
            if value and not value.startswith("{"):
                findings.append(_metadata_finding(key, value, "pymupdf"))

        xmp = doc.xref_xml_metadata() or ""
        for value in XML_VALUE_RE.findall(xmp):
            if re.search(r"[@\\]|/[A-Za-z0-9_ -]+/|corp|internal", value, re.IGNORECASE):
                findings.append(_metadata_finding("xmp_property", value, "pymupdf-xmp"))
                break

        text_parts = [page.get_text("text") for page in doc]
    return info, findings, "\n".join(text_parts)


def _docx_xml_properties(data: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    with zipfile.ZipFile(BytesIO(data)) as archive:
        for name in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
            if name not in archive.namelist():
                continue
            try:
                root = ElementTree.fromstring(archive.read(name))
            except ElementTree.ParseError:
                continue
            for element in root.iter():
                tag = element.tag.split("}")[-1]
                text = (element.text or "").strip()
                if not text or len(text) > 300:
                    continue
                if name.endswith("custom.xml") and tag == "vt:lpwstr":
                    tag = "custom_property"
                values[tag] = text
    return values


def analyze_docx(data: bytes) -> tuple[dict, list[dict], str]:
    try:
        from docx import Document  # python-docx
    except ImportError as exc:  # pragma: no cover - environment guard
        raise RuntimeError("python-docx is required for DOCX scanning. Install backend requirements.") from exc

    document = Document(BytesIO(data))
    core = document.core_properties
    values = _docx_xml_properties(data)
    for key in ("author", "last_modified_by", "title", "subject", "keywords", "comments", "category", "identifier", "revision", "version"):
        value = getattr(core, key, None)
        if value not in (None, "", 0) and key not in values:
            values[key] = str(value)

    info = {
        "paragraph_count": len(document.paragraphs),
        "table_count": len(document.tables),
        "section_count": len(document.sections),
        "metadata_fields_present": sorted(values.keys()),
        "has_custom_properties": "custom.xml" in zipfile.ZipFile(BytesIO(data)).namelist(),
    }
    findings = []
    for key, value in values.items():
        normalized = key.casefold().replace(" ", "").replace("vt:", "")
        if normalized in {"revision", "version", "pages", "words", "characters", "application", "appversion", "template"}:
            continue
        findings.append(_metadata_finding(key, value, "python-docx"))

    text_parts = [p.text for p in document.paragraphs]
    for table in document.tables:
        for row in table.rows:
            text_parts.extend(cell.text for cell in row.cells)
    for section in document.sections:
        text_parts.extend(p.text for p in section.header.paragraphs)
        text_parts.extend(p.text for p in section.footer.paragraphs)

    return info, findings, "\n".join(text_parts)
