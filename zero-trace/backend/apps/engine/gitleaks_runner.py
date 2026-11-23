"""Optional Gitleaks integration for authorized repository scans."""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from django.conf import settings

from .redaction import REDACTION_LABELS

logger = logging.getLogger(__name__)


def gitleaks_available() -> bool:
    return shutil.which(settings.ZEROTRACE["GITLEAKS_BINARY"]) is not None


def _safe_relative_path(path: str) -> Path:
    parts = [part for part in Path(path).parts if part not in {"..", "/", "\\"}]
    return Path(*parts) if parts else Path("file.txt")


def run_gitleaks(files: dict[str, str]) -> dict:
    """Scan downloaded repository files with the real gitleaks binary if installed."""
    result: dict = {"available": gitleaks_available(), "findings": [], "error": ""}
    if not result["available"] or not files:
        return result

    binary = settings.ZEROTRACE["GITLEAKS_BINARY"]
    with tempfile.TemporaryDirectory(prefix="zerotrace-gitleaks-") as temp_dir:
        root = Path(temp_dir)
        for path, content in files.items():
            target = root / _safe_relative_path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", errors="replace")
        report = root / "gitleaks-report.json"
        command = [
            binary, "detect", "--source", str(root), "--no-git",
            "--report-format", "json", "--report-path", str(report),
            "--redact", "--exit-code", "0",
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=settings.ZEROTRACE["GITLEAKS_TIMEOUT"],
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            result["error"] = str(exc)
            logger.warning("Gitleaks execution failed: %s", exc)
            return result

        if not report.exists():
            result["error"] = completed.stderr.strip()[:300]
            return result
        try:
            raw_findings = json.loads(report.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError) as exc:
            result["error"] = str(exc)
            return result

    converted = []
    for item in raw_findings if isinstance(raw_findings, list) else []:
        if not isinstance(item, dict):
            continue
        rule = str(item.get("RuleID") or "gitleaks-finding")
        path = str(item.get("File") or "unknown")
        line = str(item.get("StartLine") or "?")
        key = hashlib.sha256(f"{rule}|{path}|{line}".encode("utf-8")).hexdigest()
        converted.append(
            {
                "category": "api_key" if "key" in rule.casefold() or "token" in rule.casefold() else "credential",
                "severity": "critical",
                "title": f"Gitleaks rule: {rule}",
                "redacted_evidence": REDACTION_LABELS.get("api_key", "[REDACTED]"),
                "redacted_context": "",
                "fingerprint": key,
                "location": f"{path}:L{line}",
                "explanation": "Gitleaks identified a credential pattern in an authorized repository.",
                "remediation": "Rotate the credential and remove it from the working tree and repository history.",
                "source_tool": "gitleaks",
                "confidence": 0.99,
            }
        )
    result["findings"] = converted
    return result
