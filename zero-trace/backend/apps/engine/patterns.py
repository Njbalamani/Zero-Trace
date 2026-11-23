"""Detection patterns for privacy scanning (real, non-simulated rules)."""

from __future__ import annotations

import math
import re
from collections import Counter

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(
    r"(?<!\w)(?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)[\s.\-]?)?"
    r"\d{3,4}[\s.\-]\d{3,4}(?:[\s.\-]\d{2,4})?(?!\w)"
)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
CARD_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
PASSPORT_RE = re.compile(r"\b(?:passport(?:\s*(?:no|number|#))?)\s*[:#]?\s*[A-Z0-9]{6,9}\b", re.IGNORECASE)
CONFIDENTIAL_RE = re.compile(
    r"\b(confidential|internal use only|do not distribute|proprietary|"
    r"classified|attorney[- ]client privileged|strictly private)\b",
    re.IGNORECASE,
)
PII_LABEL_RE = re.compile(
    r"\b(?:full name|date of birth|d\.?o\.?b\.?|home address|national id|"
    r"driver'?s licen[cs]e|social security(?: number)?)\b\s*[:#]?\s*([^\n,;]{3,80})",
    re.IGNORECASE,
)

SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "api_key"),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"), "api_key"),
    ("github_fine_grained_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "api_key"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "api_key"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "api_key"),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"), "api_key"),
    ("twilio_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "api_key"),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "api_key"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "api_key"),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]{20,}?-----END [A-Z ]*PRIVATE KEY-----"),
        "credential",
    ),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|db[_-]?password|database[_-]?password|password|passwd|pwd)\b"
            r"\s*[:=]\s*[\"']?([^\"'\s,;#]{8,120})[\"']?"
        ),
        "credential",
    ),
    (
        "connection_string",
        re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s\"']{8,200}"),
        "config",
    ),
]

PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:\$\{?[A-Z0-9_]+\}?|<[^>]+>|changeme|change_me|example|placeholder|"
    r"your[_-]?(?:key|token|password|secret)|xxx+|test[_-]?value|dummy|"
    r"localhost|none|null|true|false|\*+)$"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_placeholder(value: str) -> bool:
    candidate = value.strip().strip("\"'`")
    return not candidate or bool(PLACEHOLDER_RE.fullmatch(candidate))


def is_likely_card(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        number = int(digit)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        checksum += number
    return checksum % 10 == 0


def is_likely_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return 9 <= len(digits) <= 15 and len(set(digits)) >= 4
