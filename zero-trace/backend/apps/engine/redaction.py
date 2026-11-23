"""Redaction helpers.

Only redacted evidence and salted-looking one-way fingerprints leave the
scanning engine. Raw values stay in local variables and are garbage-collected.
"""

from __future__ import annotations

import hashlib
import re

REDACTION_LABELS = {
    "email": "[REDACTED_EMAIL]",
    "phone": "[REDACTED_PHONE]",
    "api_key": "[REDACTED_API_KEY]",
    "credential": "[REDACTED_CREDENTIAL]",
    "config": "[REDACTED_CONFIG_SECRET]",
    "pii": "[REDACTED_PERSONAL_INFO]",
    "confidential": "[REDACTED_CONFIDENTIAL_TEXT]",
    "financial": "[REDACTED_FINANCIAL_ID]",
    "metadata": "[REDACTED_METADATA_VALUE]",
}


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()


def fingerprint(value: str, category: str) -> str:
    return hashlib.sha256(f"{category}:{normalize(value)}".encode("utf-8")).hexdigest()


def redact(value: str, category: str) -> str:
    """Return a non-reversible placeholder plus non-identifying metadata."""
    label = REDACTION_LABELS.get(category, "[REDACTED_SENSITIVE_VALUE]")
    token = fingerprint(value, category)[:8]
    return f"{label} (fp:{token}, len:{len(value)})"


def redact_label(value: str) -> str:
    """Remove obvious identifiers from user-visible labels such as filenames."""
    from .patterns import EMAIL_RE, PHONE_RE, is_likely_phone

    safe = EMAIL_RE.sub("[REDACTED_EMAIL]", value)
    safe = PHONE_RE.sub(lambda match: "[REDACTED_PHONE]" if is_likely_phone(match.group(0)) else match.group(0), safe)
    safe = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_ID]", safe)
    return safe[:255]


def redact_context(context: str, value: str, category: str) -> str:
    """Redact the target and every other sensitive value in a context line."""
    if not context:
        return ""
    from .patterns import (
        CARD_RE,
        EMAIL_RE,
        IBAN_RE,
        PASSPORT_RE,
        PHONE_RE,
        SECRET_PATTERNS,
        SSN_RE,
        is_likely_card,
        is_likely_phone,
    )

    escaped = re.escape(value)
    try:
        masked = re.sub(escaped, REDACTION_LABELS.get(category, "[REDACTED]"), context, flags=re.IGNORECASE)
    except re.error:
        masked = REDACTION_LABELS.get(category, "[REDACTED]")

    masked = EMAIL_RE.sub(REDACTION_LABELS["email"], masked)
    masked = PHONE_RE.sub(
        lambda match: REDACTION_LABELS["phone"] if is_likely_phone(match.group(0)) else match.group(0),
        masked,
    )
    for _, regex, secret_category in SECRET_PATTERNS:
        masked = regex.sub(REDACTION_LABELS.get(secret_category, "[REDACTED]"), masked)
    masked = SSN_RE.sub(REDACTION_LABELS["financial"], masked)
    masked = IBAN_RE.sub(REDACTION_LABELS["financial"], masked)
    masked = PASSPORT_RE.sub(REDACTION_LABELS["pii"], masked)
    masked = CARD_RE.sub(
        lambda match: REDACTION_LABELS["financial"] if is_likely_card(match.group(0)) else match.group(0),
        masked,
    )
    masked = re.sub(r"[\"'][^\"'\n]{4,120}[\"']", "[REDACTED_VALUE]", masked)
    return re.sub(r"\s+", " ", masked).strip()[:300]
