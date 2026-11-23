"""Authorized GitHub repository scanning via the public REST API.

The scanner only runs when the caller supplies an explicit authorization flag
and a token for a repository they control. Tokens are used in memory and only
their SHA-256 fingerprint is persisted by the caller.
"""

from __future__ import annotations

import base64
import logging
from typing import Callable

import requests
from django.conf import settings

from . import text_detector
from .gitleaks_runner import run_gitleaks

logger = logging.getLogger(__name__)

TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c", ".h",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties", ".sh",
    ".ps1", ".bat", ".sql", ".md", ".txt", ".xml", ".gradle", ".tf", ".tfvars", ".dockerfile",
}
CONFIG_FILENAMES = {".env", ".env.local", ".env.production", "docker-compose.yml", "docker-compose.yaml", "settings.py", "config.py", "application.properties"}
SKIP_PATH_PARTS = {"node_modules", ".git", "vendor", "__pycache__", "dist", "build", ".venv", "venv"}


class GitHubScanError(Exception):
    """User-safe GitHub scanning error (never contains a token)."""


def token_fingerprint(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def _session(token: str) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {token.strip()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ZeroTrace-Privacy-Analyzer",
        }
    )
    return session


def _request(session: requests.Session, url: str, **kwargs) -> requests.Response:
    try:
        response = session.get(url, timeout=settings.ZEROTRACE["GITHUB_TIMEOUT"], **kwargs)
    except requests.RequestException as exc:
        raise GitHubScanError("Could not reach the GitHub API. Check connectivity and try again.") from exc
    if response.status_code == 401:
        raise GitHubScanError("GitHub rejected the token. Verify that it is valid and not expired.")
    if response.status_code == 403:
        raise GitHubScanError("GitHub access is forbidden or rate-limited. Check token permissions and rate limits.")
    if response.status_code == 404:
        raise GitHubScanError("Repository not found or the token does not have access to it.")
    if not response.ok:
        raise GitHubScanError(f"GitHub API request failed with status {response.status_code}.")
    return response


def validate_token(token: str) -> str:
    session = _session(token)
    _request(session, "https://api.github.com/user")
    return token_fingerprint(token)


def _is_scannable(path: str) -> bool:
    parts = path.split("/")
    if any(part in SKIP_PATH_PARTS for part in parts):
        return False
    name = parts[-1]
    return name.casefold() in {item.casefold() for item in CONFIG_FILENAMES} or name.rsplit(".", 1)[-1].casefold() in TEXT_EXTENSIONS


def scan_repository(
    token: str,
    repository: str,
    progress: Callable[[str], None] | None = None,
) -> dict:
    if "/" not in repository or repository.count("/") != 1:
        raise GitHubScanError("Repository must be in owner/repo format.")
    owner, repo = (part.strip() for part in repository.split("/", 1))
    if not owner or not repo:
        raise GitHubScanError("Repository must be in owner/repo format.")

    session = _session(token)
    base = f"https://api.github.com/repos/{owner}/{repo}"
    metadata: dict = {"repository": repository, "authorization_verified": True}

    if progress:
        progress("Verifying repository access")
    repo_response = _request(session, base)
    repo_data = repo_response.json()
    branch = repo_data.get("default_branch") or "main"
    metadata.update(
        {
            "default_branch": branch,
            "private_repository": bool(repo_data.get("private")),
            "repository_size_kb": repo_data.get("size", 0),
        }
    )

    if progress:
        progress("Enumerating repository files")
    tree_response = _request(session, f"{base}/git/trees/{branch}?recursive=1")
    tree_data = tree_response.json()
    if tree_data.get("truncated"):
        metadata["tree_truncated"] = True
    commit_sha = tree_response.headers.get("X-GitHub-Request-Id") or tree_data.get("sha") or branch
    blobs = [entry for entry in tree_data.get("tree", []) if entry.get("type") == "blob" and _is_scannable(entry.get("path", ""))]
    max_files = settings.ZEROTRACE["MAX_REPO_FILES"]
    selected = blobs[:max_files]
    metadata.update({"files_eligible": len(blobs), "files_scanned": 0, "files_skipped": len(blobs) - len(selected)})

    findings: list[dict] = []
    file_contents: dict[str, str] = {}
    max_bytes = settings.ZEROTRACE["MAX_REPO_FILE_BYTES"]

    for index, entry in enumerate(selected, start=1):
        path = entry.get("path", "")
        if entry.get("size", 0) > max_bytes:
            metadata["files_skipped"] += 1
            continue
        if progress and index % 10 == 0:
            progress(f"Scanning files ({index}/{len(selected)})")
        response = _request(session, f"{base}/contents/{path}", params={"ref": branch})
        try:
            payload = response.json()
            content = base64.b64decode(payload.get("content", "")).decode("utf-8", errors="replace")
        except (ValueError, KeyError, base64.binascii.Error) as exc:
            logger.warning("Skipping unreadable file in %s", repository)
            metadata["files_skipped"] += 1
            continue
        if not content.strip():
            continue
        file_contents[path] = content
        findings.extend(text_detector.detect_text(content, source=path))
        metadata["files_scanned"] += 1

    if progress:
        progress("Running Gitleaks engine")
    gitleaks = run_gitleaks(file_contents)
    findings.extend(gitleaks["findings"])
    metadata["gitleaks_available"] = gitleaks["available"]
    if gitleaks["error"]:
        metadata["gitleaks_error"] = gitleaks["error"][:200]

    unique_findings = text_detector.dedupe(findings)
    return {
        "source_name": repository[:255],
        "source_hash": commit_sha[:64],
        "mime_type": "application/x-git-repository",
        "size_bytes": sum(len(value.encode("utf-8")) for value in file_contents.values()),
        "metadata": metadata,
        "findings": unique_findings,
        "text_length": sum(len(value) for value in file_contents.values()),
    }
