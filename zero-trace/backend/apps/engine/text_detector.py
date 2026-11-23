"""Regex, entropy and rule-based text detection."""

from __future__ import annotations

import re
from typing import Iterable

from . import patterns
from .redaction import fingerprint, redact, redact_context

EXPLANATIONS = {
    "email": "Email addresses are personally identifiable and often used for account takeover, phishing and identity correlation.",
    "phone": "Phone numbers can identify a person and enable SIM-swap, SMS phishing and unwanted contact.",
    "api_key": "A live API key grants programmatic access to a service and may allow data theft or billable usage.",
    "credential": "Hardcoded credentials allow anyone with file or repository access to authenticate as a user or service.",
    "config": "Configuration strings frequently embed usernames, passwords, hosts and internal network details.",
    "pii": "Direct personal identifiers increase identity-theft risk and may be subject to privacy regulations.",
    "confidential": "Confidentiality markers indicate content that was not intended for public distribution.",
    "financial": "Financial identifiers can enable fraud and are heavily regulated.",
}

REMEDIATIONS = {
    "email": "Replace with a role-based address or remove it. If it must appear, obtain consent and minimise context.",
    "phone": "Remove the number or replace it with a generic contact channel.",
    "api_key": "Revoke and rotate the key immediately, then load it from a secret manager or environment variable. Add the file to .gitignore if applicable.",
    "credential": "Rotate the credential, remove it from source files and history, and inject it at runtime from a vault.",
    "config": "Externalise the connection string into environment-specific secret storage and scrub it from version control.",
    "pii": "Remove or anonymise the identifier. Apply data minimisation and document a lawful basis if retention is required.",
    "confidential": "Verify distribution permissions, remove the document from public locations and apply classification labels.",
    "financial": "Remove the identifier, use tokenisation and restrict access to authorised finance systems only.",
}


def make_finding(
    category: str,
    severity: str,
    title: str,
    raw: str,
    location: str,
    explanation: str,
    remediation: str,
    source_tool: str = "regex",
    confidence: float = 1.0,
    context: str = "",
) -> dict:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "redacted_evidence": redact(raw, category),
        "redacted_context": redact_context(context or raw, raw, category),
        "fingerprint": fingerprint(raw, category),
        "location": location,
        "explanation": explanation,
        "remediation": remediation,
        "source_tool": source_tool,
        "confidence": confidence,
    }


def _line(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _context(text: str, start: int, end: int) -> str:
    return text[max(0, start - 70) : min(len(text), end + 70)]


def dedupe(findings: Iterable[dict]) -> list[dict]:
    seen: set[str] = set()
    unique: list[dict] = []
    for finding in findings:
        key = finding["fingerprint"]
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def detect_text(text: str, source: str = "document") -> list[dict]:
    findings: list[dict] = []
    if not text or not text.strip():
        return findings

    for match in patterns.EMAIL_RE.finditer(text):
        findings.append(
            make_finding(
                "email", "medium", "Email address exposed", match.group(0),
                f"{source}:L{_line(text, match.start())}",
                EXPLANATIONS["email"], REMEDIATIONS["email"],
                context=_context(text, match.start(), match.end()),
            )
        )

    for match in patterns.PHONE_RE.finditer(text):
        value = match.group(0)
        if patterns.is_likely_phone(value):
            findings.append(
                make_finding(
                    "phone", "medium", "Phone number exposed", value,
                    f"{source}:L{_line(text, match.start())}",
                    EXPLANATIONS["phone"], REMEDIATIONS["phone"], confidence=0.9,
                    context=_context(text, match.start(), match.end()),
                )
            )

    for name, regex, category in patterns.SECRET_PATTERNS:
        for match in regex.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            if patterns.is_placeholder(value):
                continue
            severity = "critical" if category in {"api_key", "credential", "config"} else "high"
            entropy = patterns.shannon_entropy(value)
            confidence = 0.99 if name != "credential_assignment" else min(0.98, 0.65 + entropy / 20)
            if name == "credential_assignment" and entropy < 2.5:
                confidence = 0.6
            findings.append(
                make_finding(
                    category, severity, f"Possible {name.replace('_', ' ')}", match.group(0),
                    f"{source}:L{_line(text, match.start())}",
                    EXPLANATIONS[category], REMEDIATIONS[category],
                    source_tool="regex+entropy", confidence=confidence,
                    context=_context(text, match.start(), match.end()),
                )
            )

    for match in patterns.SSN_RE.finditer(text):
        findings.append(
            make_finding(
                "financial", "critical", "US Social Security number pattern", match.group(0),
                f"{source}:L{_line(text, match.start())}",
                EXPLANATIONS["financial"], REMEDIATIONS["financial"], confidence=0.9,
                context=_context(text, match.start(), match.end()),
            )
        )

    for match in patterns.IBAN_RE.finditer(text):
        findings.append(
            make_finding(
                "financial", "high", "IBAN pattern", match.group(0),
                f"{source}:L{_line(text, match.start())}",
                EXPLANATIONS["financial"], REMEDIATIONS["financial"], confidence=0.8,
                context=_context(text, match.start(), match.end()),
            )
        )

    for match in patterns.CARD_RE.finditer(text):
        value = match.group(0)
        if patterns.is_likely_card(value):
            findings.append(
                make_finding(
                    "financial", "critical", "Payment card number (Luhn valid)", value,
                    f"{source}:L{_line(text, match.start())}",
                    EXPLANATIONS["financial"], REMEDIATIONS["financial"],
                    source_tool="regex+luhn", confidence=0.97,
                    context=_context(text, match.start(), match.end()),
                )
            )

    for match in patterns.PASSPORT_RE.finditer(text):
        findings.append(
            make_finding(
                "pii", "high", "Passport identifier", match.group(0),
                f"{source}:L{_line(text, match.start())}",
                EXPLANATIONS["pii"], REMEDIATIONS["pii"], confidence=0.75,
                context=_context(text, match.start(), match.end()),
            )
        )

    for match in patterns.PII_LABEL_RE.finditer(text):
        value = match.group(1)
        if patterns.is_placeholder(value):
            continue
        findings.append(
            make_finding(
                "pii", "high", f"Labelled personal information: {match.group(0).split(':')[0].strip()}",
                value, f"{source}:L{_line(text, match.start())}",
                EXPLANATIONS["pii"], REMEDIATIONS["pii"], confidence=0.85,
                context=_context(text, match.start(), match.end()),
            )
        )

    for match in patterns.CONFIDENTIAL_RE.finditer(text):
        findings.append(
            make_finding(
                "confidential", "low", f"Confidentiality marker: {match.group(0)}", match.group(0),
                f"{source}:L{_line(text, match.start())}",
                EXPLANATIONS["confidential"], REMEDIATIONS["confidential"],
                context=_context(text, match.start(), match.end()),
            )
        )

    return dedupe(findings)
