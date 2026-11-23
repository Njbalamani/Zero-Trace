"""NLP-based personal information detection with graceful model fallback."""

from __future__ import annotations

import re
from functools import lru_cache

from django.conf import settings

from .text_detector import dedupe, make_finding

HONORIFIC_NAME_RE = re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b")
NAMED_FIELD_RE = re.compile(r"\b(?:name|employee|contact|signatory|witness)\s*[:=]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b")


@lru_cache(maxsize=1)
def _load_nlp():
    try:
        import spacy  # type: ignore
    except ImportError:
        return None
    try:
        return spacy.load(settings.ZEROTRACE["SPACY_MODEL"])
    except (OSError, ValueError):
        return None


def detector_status() -> dict:
    return {"spacy_model_loaded": _load_nlp() is not None, "model": settings.ZEROTRACE["SPACY_MODEL"]}


def detect_pii(text: str, source: str = "document") -> list[dict]:
    findings: list[dict] = []
    if not text:
        return findings

    nlp = _load_nlp()
    if nlp is not None:
        doc = nlp(text)
        for entity in doc.ents:
            if entity.label_ == "PERSON":
                findings.append(
                    make_finding(
                        "pii", "medium", "Person name (NLP)", entity.text,
                        f"{source}:NLP",
                        "A named individual can be linked to other datasets to build a digital footprint.",
                        "Remove the name, replace it with a role, or confirm there is a legitimate reason to publish it.",
                        source_tool="spacy-ner", confidence=0.82,
                    )
                )
            elif entity.label_ in {"GPE", "LOC"} and len(entity.text.split()) <= 3:
                findings.append(
                    make_finding(
                        "pii", "low", f"Location reference (NLP): {entity.text}", entity.text,
                        f"{source}:NLP",
                        "Location references can contribute to re-identification when combined with other details.",
                        "Generalise or remove precise locations where they are not necessary.",
                        source_tool="spacy-ner", confidence=0.55,
                    )
                )
    else:
        for regex, confidence in ((HONORIFIC_NAME_RE, 0.75), (NAMED_FIELD_RE, 0.7)):
            for match in regex.finditer(text):
                value = match.group(1) if match.lastindex else match.group(0)
                findings.append(
                    make_finding(
                        "pii", "medium", "Possible person name (pattern)", value,
                        f"{source}:L{text.count(chr(10), 0, match.start()) + 1}",
                        "A named individual can be linked to other datasets to build a digital footprint.",
                        "Remove the name, replace it with a role, or confirm there is a legitimate reason to publish it.",
                        source_tool="regex-nlp-fallback", confidence=confidence,
                    )
                )

    return dedupe(findings)
