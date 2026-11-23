# ZeroTrace Architecture

## System overview

```mermaid
flowchart TB
    U[User / Privacy Analyst] -->|HTTPS| FE[React SPA\nVite + Chart.js]
    FE -->|REST / Token| API[Django REST API]
    API --> DB[(PostgreSQL)]
    API --> ENG[Scanning Engine]
    API --> SAN[Clean-copy sanitizer\nPyMuPDF / python-docx]
    API --> RPT[ReportLab]
    API --> AUD[Audit events]
    API -.->|Opt-in only, redacted metadata| GEM[Google Gemini API]
    ENG --> DOC[PyMuPDF / python-docx\ntext + metadata extraction]
    ENG --> NLP[spaCy NER + regex fallback]
    ENG --> SEC[Regex / entropy / Luhn\nsecret detectors]
    ENG --> GH[GitHub REST API\nauthorized repositories only]
    ENG --> GL[Gitleaks binary\noptional, local temp files]
    GH --> REPO[(Authorized repository)]
```

## Request flow: document scan

```mermaid
sequenceDiagram
    participant U as User
    participant FE as React SPA
    participant API as Django API
    participant ENG as Scanning Engine
    participant DB as Database

    U->>FE: Select PDF/DOCX
    FE->>API: POST /scans/documents/ (multipart)
    API->>DB: Create Scan(running)
    API->>ENG: scan_document(filename, bytes)
    ENG->>ENG: Extract text + metadata in memory
    ENG->>ENG: Run regex, entropy, Luhn, spaCy NER
    ENG-->>API: Findings with redacted evidence + fingerprints
    API->>API: Calculate risk + recommendations
    API-->>GEM: Only if consent + API key (redacted metadata)
    API->>DB: Store Scan, Finding, Recommendation
    DB-->>API: Persisted records
    API-->>FE: 201 + redacted scan detail
    FE-->>U: Results dashboard
```

## Expansion flows

- **Batch scan:** the API accepts repeated `files` parts, validates each upload, then reuses the same in-memory `scan_document()` engine per file. Successful and failed items are returned separately, and each successful item creates its own `Scan`, `Finding` and `Recommendation` records.
- **Sanitizer:** `apps/engine/sanitizer.py` rewrites PDF/DOCX bytes in memory, clears metadata dictionaries and streams the clean copy directly to the client. No sanitized or original file is persisted.
- **False-positive review:** `POST /findings/<id>/review/` toggles `Finding.false_positive`, recalculates `Scan.risk_score`, `risk_level` and `summary`, writes an audit event and returns full updated scan detail.
- **Audit and timeline:** `apps/scans/audit.py` writes small structured events for login, consent, scans, sanitization and reviews. Dashboard `risk_timeline` is derived from completed scans and feeds the React risk chart.

## Request flow: repository scan

```mermaid
sequenceDiagram
    participant U as User
    participant FE as React SPA
    participant API as Django API
    participant GH as GitHub API
    participant ENG as Scanner
    participant GL as Gitleaks
    participant DB as Database

    U->>FE: Repository + token + explicit authorization
    FE->>API: POST /scans/repositories/ {authorize:true}
    API->>GH: Validate token (GET /user)
    GH-->>API: Valid
    API->>DB: Store/refresh token fingerprint + authorization
    API->>DB: Create Scan(running)
    API->>GH: Repo metadata + recursive tree
    loop Each eligible text/config file
        API->>GH: Fetch file content (base64)
        GH-->>API: File bytes
        API->>ENG: Run secret/PII detectors
    end
    API->>GL: Optional gitleaks detect on temp files
    GL-->>API: JSON findings (redacted)
    API->>DB: Store redacted findings + risk
    API-->>FE: 201 + redacted scan detail
```

## Privacy boundaries

```mermaid
flowchart LR
    subgraph Client
        A[Uploaded document bytes]
    end
    subgraph BackendMemory
        B[In-memory extraction]
        C[Raw match in local variable]
        D[Redaction + fingerprint]
    end
    subgraph Persistent
        E[Redacted findings]
        F[Hashed token fingerprint]
        G[Scan metadata keys/counts]
    end
    subgraph External
        H[GitHub API\nuser authorized]
        I[Gemini API\nopt-in, metadata only]
    end
    A --> B --> C --> D --> E
    C -.->|never persisted| X[Discarded]
    D --> I
    H --> B
    F --> G
```

## Components

| Component | Responsibility |
| --- | --- |
| `apps/accounts` | Custom user model, AI consent flag, token authentication |
| `apps/api` | REST serializers, views, routes, integration tests |
| `apps/scans` | Scan, Finding, Recommendation, RepositoryAuthorization and AuditEvent models; `audit.py` event helper |
| `apps/engine/document_scanner.py` | Orchestrates in-memory PDF/DOCX processing |
| `apps/engine/metadata_analyzer.py` | PyMuPDF/python-docx metadata and XMP/custom property inspection |
| `apps/engine/text_detector.py` | Emails, phones, secrets, financial identifiers, confidential markers |
| `apps/engine/nlp_detector.py` | spaCy NER with regex fallback |
| `apps/engine/github_scanner.py` | Authorized GitHub REST scanning |
| `apps/engine/gitleaks_runner.py` | Local Gitleaks subprocess wrapper |
| `apps/engine/risk_engine.py` | Scoring, recommendations, consent-gated AI narrative |
| `apps/engine/report_generator.py` | Redacted PDF report |
| `apps/engine/sanitizer.py` | Real PDF/DOCX metadata and attachment cleanup |
| `frontend/src` | React SPA with dashboard, scanners, batch scans, privacy tools, history, detail, audit trail and settings |

## Deployment topology

```mermaid
flowchart LR
    Internet -->|443| Nginx
    Nginx -->|/api proxy| Gunicorn[Django + Gunicorn]
    Nginx -->|static| ReactBuild[React production bundle]
    Gunicorn --> PostgreSQL
    Gunicorn --> Temp[Ephemeral temp dirs\nGitleaks only]
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for configuration details and [ER_DIAGRAM.md](ER_DIAGRAM.md) for the database schema.
