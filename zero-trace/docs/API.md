# ZeroTrace REST API Documentation

Base URL (local development): `http://127.0.0.1:8000/api/`

All endpoints except `health/`, `auth/register/` and `auth/login/` require:

```http
Authorization: Token <token>
```

Responses are JSON except the PDF report endpoint. All finding fields are redacted; raw detected values are never returned.

## Health

### `GET /health/`

```json
{
  "status": "ok",
  "service": "ZeroTrace Privacy Analyzer",
  "detectors": { "spacy_model_loaded": true, "model": "en_core_web_sm" },
  "files_supported": [".pdf", ".docx"],
  "external_ai": "opt-in only"
}
```

## Authentication

### `POST /auth/register/`

```json
{
  "username": "analyst",
  "email": "analyst@example.com",
  "password": "Str0ng!Passphrase42"
}
```

`201 Created`

```json
{
  "token": "99e...",
  "user": { "id": 1, "username": "analyst", "email": "analyst@example.com", "ai_consent": false, "ai_consent_at": null, "date_joined": "2026-11-23T10:00:00Z" }
}
```

### `POST /auth/login/`

```json
{ "email": "analyst@example.com", "password": "Str0ng!Passphrase42" }
```

Returns the same shape as registration. Invalid credentials return `401`.

### `POST /auth/logout/`

Deletes the current token. `200 OK`.

### `GET /auth/me/`

Returns the current user object.

### `POST /auth/consent/`

```json
{ "ai_consent": true }
```

Updates the explicit consent flag and records `ai_consent_at`. External AI remains inactive if `GEMINI_API_KEY` is not configured.

## Document scan

### `POST /scans/documents/`

`multipart/form-data` with field `file` (PDF or DOCX, max 20 MB).

```powershell
curl -X POST http://127.0.0.1:8000/api/scans/documents/ `
  -H "Authorization: Token $token" `
  -F "file=@C:\reports\quarterly.pdf"
```

`201 Created` response (abbreviated):

```json
{
  "id": "8b1e...uuid",
  "scan_type": "document",
  "status": "completed",
  "source_name": "[REDACTED_EMAIL]-quarterly.pdf",
  "risk_score": 57,
  "risk_level": "high",
  "metadata": { "page_count": 4, "metadata_fields_present": ["author", "title"] },
  "summary": {
    "total": 7,
    "by_severity": { "critical": 1, "high": 2, "medium": 3, "low": 1, "info": 0 },
    "by_category": { "api_key": 1, "email": 2, "metadata": 2 },
    "critical_count": 1,
    "score": 57,
    "level": "high"
  },
  "ai_summary": "Privacy scan identified 7 finding(s)...",
  "ai_used": false,
  "findings": [
    {
      "id": 12,
      "category": "api_key",
      "severity": "critical",
      "title": "Possible aws access key",
      "redacted_evidence": "[REDACTED_API_KEY] (fp:6f48db16, len:20)",
      "redacted_context": "AWS_ACCESS_KEY_ID=[REDACTED_API_KEY] ...",
      "location": "content:L3",
      "explanation": "A live API key grants programmatic access...",
      "remediation": "Revoke and rotate the key immediately...",
      "source_tool": "regex+entropy",
      "confidence": 0.99
    }
  ],
  "recommendations": [
    { "priority": 1, "title": "Rotate and revoke exposed credentials immediately", "action_key": "rotate_credentials" }
  ]
}
```

Unsupported extensions or empty files return `400`.

### `POST /scans/documents/batch/`

`multipart/form-data` with repeated field `files` (2–10 PDF/DOCX files, 20 MB each). Files are scanned independently, so one invalid or failing file does not block the rest.

```powershell
curl -X POST http://127.0.0.1:8000/api/scans/documents/batch/ `
  -H "Authorization: Token $token" `
  -F "files=@C:\reports\quarterly.pdf" `
  -F "files=@C:\reports\brief.docx"
```

`201 Created`

```json
{
  "total": 2,
  "completed_count": 2,
  "failed_count": 0,
  "completed": [{ "id": "8b1e...uuid", "source_name": "[REDACTED_EMAIL]-quarterly.pdf", "risk_score": 57 }],
  "failed": []
}
```

## Authorized repository scan

### `POST /scans/repositories/`

```json
{
  "repository": "acme/app",
  "token": "ghp_placeholder",
  "authorize": true
}
```

`authorize` must be exactly `true`; otherwise the API returns `400` and no scan is created. The token is validated with GitHub before scanning, used only in memory, and persisted solely as a SHA-256 fingerprint on the `RepositoryAuthorization` record.

Response shape matches the document scan response. `metadata` includes `files_scanned`, `files_skipped`, `default_branch`, `private_repository`, `tree_truncated`, `gitleaks_available` and optional `gitleaks_error`.

Common errors:

| Status | Meaning |
| --- | --- |
| 400 | Missing authorization, invalid repository format, invalid/expired token, forbidden or rate-limited GitHub access |
| 500 | Unexpected scanner failure (no token or repository content is logged) |

## Scan history and detail

### `GET /scans/?scan_type=document&limit=50`

Returns scans belonging to the authenticated user, newest first. `scan_type` may be `document` or `repository`; `limit` is 1–200.

### `GET /scans/<uuid>/`

Returns full redacted detail for a scan owned by the caller. Other users' scans return `404`.

### `GET /scans/<uuid>/report/`

Streams a `application/pdf` report with redacted evidence. Filename: `zerotrace-report-<uuid>.pdf`.

### `POST /findings/<id>/review/`

Marks a finding as a false positive or restores it. The scan's risk score, risk level and severity summary are recalculated and the full updated scan detail is returned.

```json
{ "false_positive": true }
```

`200 OK` returns the same shape as `GET /scans/<uuid>/`, with `false_positive: true` on the reviewed finding. An `AuditEvent` with action `finding_reviewed` is recorded.

## Privacy tools

### `POST /tools/sanitize/`

`multipart/form-data` with field `file` (PDF or DOCX, max 20 MB). Returns a streamed `application/octet-stream` clean copy with `Content-Disposition: attachment; filename="<name>-clean.<ext>"`.

The sanitizer clears PDF info fields and XMP metadata, removes embedded PDF attachments, clears DOCX core author fields, deletes `docProps/custom.xml` and scrubs Company/Manager values from `docProps/app.xml`. The original bytes are never persisted and document body content is preserved.

```powershell
curl -X POST http://127.0.0.1:8000/api/tools/sanitize/ `
  -H "Authorization: Token $token" `
  -F "file=@C:\reports\quarterly.pdf" `
  -o quarterly-clean.pdf
```

Unsupported extensions or empty files return `400`.

## Audit trail

### `GET /audit/`

Returns the current user's latest 100 privacy-safe audit events, newest first. Metadata contains counts, booleans and status values only — never raw document text, secrets or tokens.

```json
[
  {
    "id": 1,
    "action": "document_scan",
    "target": "report.docx",
    "metadata": { "status": "completed", "risk_level": "high", "findings": 7 },
    "created_at": "2026-11-23T10:05:00Z"
  }
]
```

## Dashboard

### `GET /dashboard/`

```json
{
  "totals": {
    "scans": 12, "documents": 9, "repositories": 3, "completed": 11,
    "failed": 1, "findings": 47, "critical": 6, "high": 12
  },
  "risk_distribution": { "critical": 2, "high": 3, "medium": 4, "low": 2 },
  "severity_distribution": { "critical": 6, "high": 12, "medium": 18, "low": 10, "info": 1 },
  "category_distribution": { "email": 15, "api_key": 8 },
  "scan_trend": [{ "date": "2026-11-17", "count": 2 }],
  "risk_timeline": [{ "date": "2026-11-23T10:05:00Z", "score": 57, "level": "high" }],
  "privacy_improvement": { "percent": 18.5, "interpretation": "Positive means recent scans show lower risk than earlier scans." },
  "recent_scans": []
}
```

`risk_timeline` contains the latest 12 completed scans ordered oldest to newest and powers the dashboard risk-score chart.

## Recommendations and findings

### `GET /recommendations/`

Returns up to 80 recommendations across the caller's scans, ordered by priority.

### `GET /findings/?severity=critical`

Returns up to 200 redacted findings. Optional `severity` filter: `critical`, `high`, `medium`, `low`, `info`.

## Risk scoring

Severity weights: critical 25, high 15, medium 7, low 3, info 1. The sum is capped at 100.

| Score | Risk level |
| --- | --- |
| 75–100 | critical |
| 50–74 | high |
| 25–49 | medium |
| 10–24 | low |
| 0–9 | minimal |

## Redaction contract

Every finding includes:

- `redacted_evidence` — placeholder such as `[REDACTED_API_KEY] (fp:..., len:20)`
- `redacted_context` — nearby text with all detected identifiers/secrets masked
- `fingerprint` — SHA-256 of category + normalized raw value; not reversible
- `location` — page/line, NLP marker or repository path/line

No API endpoint returns the raw matched value.
