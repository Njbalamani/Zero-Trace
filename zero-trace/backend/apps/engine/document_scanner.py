"""Orchestration of PDF/DOCX privacy scanning (in-memory only)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from django.conf import settings

from . import metadata_analyzer, nlp_detector, text_detector

ALLOWED_EXTENSIONS = {".pdf", ".docx"}
MIME_TYPES = {".pdf": "application/pdf", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}


def scan_document(filename: str, data: bytes) -> dict:
    extension = Path(filename).suffix.casefold()
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Only PDF and DOCX files are supported.")
    max_bytes = int(settings.FILE_UPLOAD_MAX_MEMORY_SIZE)
    if not data:
        raise ValueError("The uploaded file is empty.")
    if len(data) > max_bytes:
        raise ValueError(f"File exceeds the {max_bytes // (1024 * 1024)} MB upload limit.")

    if extension == ".pdf":
        metadata, metadata_findings, text = metadata_analyzer.analyze_pdf(data)
    else:
        metadata, metadata_findings, text = metadata_analyzer.analyze_docx(data)

    findings = metadata_findings
    findings += text_detector.detect_text(text, source="content")
    findings += nlp_detector.detect_pii(text, source="content")
    findings = text_detector.dedupe(findings)

    return {
        "source_name": Path(filename).name[:255],
        "source_hash": hashlib.sha256(data).hexdigest(),
        "mime_type": MIME_TYPES[extension],
        "size_bytes": len(data),
        "metadata": metadata,
        "findings": findings,
        "text_length": len(text),
        "detector_status": nlp_detector.detector_status(),
    }
