"""Risk scoring, recommendation generation and optional AI assessment.

External AI is used only with explicit user consent and receives redacted
finding metadata only -- never document contents or raw detected values.
"""

from __future__ import annotations

import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

RECOMMENDATION_TEMPLATES = [
    {
        "key": "rotate_credentials",
        "categories": {"api_key", "credential", "config"},
        "title": "Rotate and revoke exposed credentials immediately",
        "description": "Treat every detected key or password as compromised. Revoke it at the provider, issue a replacement with least privilege, and load it from a managed secret store at runtime.",
        "priority": 1,
        "category": "credential",
    },
    {
        "key": "protect_financial",
        "categories": {"financial"},
        "title": "Escalate financial identifier exposure",
        "description": "Remove payment or government identifiers, notify your privacy/security owner, and use tokenisation or masking in any system that must retain them.",
        "priority": 1,
        "category": "financial",
    },
    {
        "key": "strip_metadata",
        "categories": {"metadata"},
        "title": "Strip document metadata before sharing",
        "description": "Clear author, last-modified-by, custom properties and XMP fields with a metadata removal tool, then re-scan the exported copy.",
        "priority": 2,
        "category": "metadata",
    },
    {
        "key": "minimise_identifiers",
        "categories": {"email", "phone", "pii"},
        "title": "Minimise direct personal identifiers",
        "description": "Replace personal names, emails and phone numbers with role-based or generic values unless there is a documented need to publish them.",
        "priority": 3,
        "category": "pii",
    },
    {
        "key": "review_classification",
        "categories": {"confidential"},
        "title": "Review document classification and distribution",
        "description": "Confirm the content is authorised for release, remove confidentiality markers from public copies, and apply access controls internally.",
        "priority": 4,
        "category": "confidential",
    },
    {
        "key": "add_precommit_scanning",
        "categories": {"api_key", "credential", "config"},
        "title": "Add automated secret scanning to CI",
        "description": "Run Gitleaks in pre-commit hooks and CI, enable provider push protection, and add build-time failure for high-confidence detections.",
        "priority": 5,
        "category": "process",
    },
]


def calculate_risk(findings: list[dict]) -> dict:
    by_severity = {level: 0 for level in SEVERITY_ORDER}
    by_category: dict[str, int] = {}
    for finding in findings:
        level = finding.get("severity", "info")
        by_severity[level] = by_severity.get(level, 0) + 1
        category = finding.get("category", "other")
        by_category[category] = by_category.get(category, 0) + 1

    raw_score = sum(SEVERITY_WEIGHTS.get(level, 1) * count for level, count in by_severity.items())
    score = min(100, raw_score)
    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    elif score >= 10:
        level = "low"
    else:
        level = "minimal"

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "critical_count": by_severity.get("critical", 0),
        "score": score,
        "level": level,
    }


def build_recommendations(findings: list[dict]) -> list[dict]:
    categories = {finding.get("category") for finding in findings}
    recommendations = []
    for template in RECOMMENDATION_TEMPLATES:
        if categories.intersection(template["categories"]):
            recommendations.append(
                {
                    "title": template["title"],
                    "description": template["description"],
                    "priority": template["priority"],
                    "category": template["category"],
                    "action_key": template["key"],
                }
            )
    if not recommendations:
        recommendations.append(
            {
                "title": "Maintain privacy hygiene",
                "description": "No high-priority remediation was identified. Continue periodic scans and keep data minimisation practices in place.",
                "priority": 9,
                "category": "general",
                "action_key": "maintain_hygiene",
            }
        )
    return sorted(recommendations, key=lambda item: item["priority"])


def deterministic_summary(summary: dict) -> str:
    severity = summary["by_severity"]
    top = ", ".join(f"{category} ({count})" for category, count in sorted(summary["by_category"].items(), key=lambda item: -item[1])[:3])
    return (
        f"Privacy scan identified {summary['total']} finding(s) with an overall risk score of "
        f"{summary['score']}/100 ({summary['level']}). Severity breakdown: "
        f"{severity['critical']} critical, {severity['high']} high, {severity['medium']} medium, "
        f"{severity['low']} low. "
        + (f"Most affected categories: {top}. " if top else "")
        + "Prioritise remediation of critical credential and identifier exposures."
    )


def ai_assessment(summary: dict, findings: list[dict], consent: bool) -> tuple[str, bool]:
    fallback = deterministic_summary(summary)
    config = settings.ZEROTRACE
    api_key = config["GEMINI_API_KEY"]
    if not consent or not api_key:
        return fallback, False

    safe_findings = [
        {
            "category": item.get("category"),
            "severity": item.get("severity"),
            "title": item.get("title"),
            "location": item.get("location"),
            "evidence": item.get("redacted_evidence"),
        }
        for item in findings[:60]
    ]
    prompt = (
        "You are a privacy engineer. Summarise this REDACTED privacy scan result in 3 short paragraphs. "
        "Explain why the top risks matter and give concrete prioritised remediation steps. "
        "Never ask for or attempt to reconstruct sensitive values.\n\n"
        f"Risk score: {summary['score']}/100 ({summary['level']}).\n"
        f"Counts: {summary['by_severity']}.\n"
        f"Findings (redacted): {safe_findings}.\n"
    )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{config['GEMINI_MODEL']}:generateContent"
    try:
        response = requests.post(
            url,
            params={"key": api_key},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 600},
            },
            timeout=20,
        )
        response.raise_for_status()
        text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        return str(text).strip(), True
    except (requests.RequestException, KeyError, IndexError, TypeError) as exc:
        logger.warning("Gemini assessment unavailable, using deterministic summary: %s", exc)
        return fallback, False
