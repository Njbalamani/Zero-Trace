# ZeroTrace — AI-Powered Privacy Leak Detection & Digital Footprint Analyzer

ZeroTrace is a full-stack privacy protection platform that identifies sensitive information exposure in user-provided PDF/DOCX documents and explicitly authorized GitHub repositories. It uses real scanning engines (PyMuPDF, python-docx, spaCy NER, regex/entropy/Luhn rules, GitHub REST API and optional Gitleaks), calculates a weighted privacy risk score, and produces redacted PDF reports with prioritized remediation guidance.

> Uploaded documents are processed in memory, never persisted, and never sent to an external AI service unless the user explicitly opts in. Detected secrets are never stored or returned in clear text.

## Contents

- [Key capabilities](#key-capabilities)
- [Privacy and security model](#privacy-and-security-model)
- [Technology stack](#technology-stack)
- [Project structure](#project-structure)
- [Quick start (Windows / local development)](#quick-start-windows--local-development)
- [Docker deployment](#docker-deployment)
- [Configuration](#configuration)
- [API overview](#api-overview)
- [Testing](#testing)
- [Documentation](#documentation)
- [License](#license)

## Key capabilities

1. **Authentication and user management** — Django custom user, token auth, registration, login, logout and explicit AI consent state.
2. **PDF/DOCX privacy scanner** — extracts text with PyMuPDF/python-docx and analyses author, last-modified-by, custom and XMP metadata.
3. **Personal information detection** — spaCy named-entity recognition (PERSON, GPE/LOC) with a regex fallback when the model is unavailable.
4. **Credential exposure detection** — detects AWS keys, GitHub tokens, Google API keys, Slack tokens, Stripe keys, JWTs, private-key blocks, password assignments, connection strings and high-entropy values.
5. **Authorized GitHub repository scanning** — validates a supplied token, requires an explicit `authorize: true` flag, enumerates text/config files through the GitHub REST API and scans them with the same engines.
6. **Optional Gitleaks integration** — runs the real `gitleaks detect` binary against temporarily downloaded authorized repository files when installed; otherwise the API reports that Gitleaks is unavailable and regex/entropy scanning still runs.
7. **AI privacy risk assessment** — deterministic severity-weighted scoring plus optional Google Gemini narrative that receives only redacted finding metadata after opt-in.
8. **Recommendation engine** — generates prioritized remediation steps based on detected categories.
9. **Interactive analytics dashboard** — Chart.js doughnut/bar/line charts, KPI cards, scan activity and privacy improvement trend.
10. **Redacted PDF reports** — ReportLab-generated reports containing redacted evidence, fingerprints, risk assessment and remediation plan.
11. **Batch document scanning** — Upload up to 10 PDF/DOCX files in one request and receive separate risk-scored results.
12. **Metadata sanitizer** — Generate a real clean copy of a PDF/DOCX with author, custom properties, XMP metadata and embedded attachments removed.
13. **False-positive review** — Dismiss findings with one click; scan risk score and severity distribution recalculate immediately.
14. **Audit trail and risk timeline** — Privacy-safe activity log plus a 12-point risk-score trend chart on the dashboard.

## Privacy and security model

| Control | Implementation |
| --- | --- |
| No repository scanning without authorization | `authorize: true` is mandatory; token is validated before scanning; only `owner/repo` supplied by the user is accessed. |
| No raw secret exposure | Findings store `redacted_evidence`, `redacted_context` and a SHA-256 fingerprint only. |
| No unnecessary personal data storage | Uploaded files are never written to disk; scan metadata stores presence/keys, not raw metadata values. |
| No document content sent to external AI | Gemini receives only category, severity, title, location and redacted evidence, and only when `ai_consent` is true. |
| No token persistence | GitHub tokens are used in memory; only a SHA-256 `token_fingerprint` is stored. |
| Redacted reports | PDF report generation uses only redacted fields and a sanitized source label. |
| Tenant isolation | Every scan/finding/recommendation query is filtered by the authenticated user. |

## Technology stack

| Layer | Technology |
| --- | --- |
| Frontend | React 18, Vite, React Router, Chart.js, custom CSS (no Bootstrap) |
| Backend | Python 3.12, Django 5.1, Django REST Framework, Token Auth |
| Database | PostgreSQL (production/docker), SQLite fallback for local dev |
| NLP | spaCy `en_core_web_sm`, regex, Shannon entropy, Luhn validation |
| Documents | PyMuPDF, python-docx |
| Secret scanning | Custom detectors + optional Gitleaks binary |
| Reporting | ReportLab |
| AI | Google Gemini API (optional, consent-gated) |

## Project structure

```text
ZeroTrace-Privacy-Analyzer/
├── backend/
│   ├── apps/
│   │   ├── accounts/          # Custom user + consent
│   │   ├── api/               # Serializers, views, URLs, tests
│   │   ├── engine/            # Scanning engines and report generator
│   │   └── scans/             # Models and migrations
│   ├── zerotrace/             # Settings, URLs, WSGI/ASGI
│   ├── manage.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/        # Layout, charts, UI primitives, icons
│   │   ├── context/           # Auth context
│   │   ├── pages/             # Dashboard, scanners, history, detail, settings
│   │   ├── services/          # Axios API client
│   │   └── styles/            # Custom CSS
│   └── package.json
├── deployment/                # Docker and reverse-proxy configuration
├── docs/                      # API, architecture, ER diagram, deployment
├── LICENSE                    # MIT
└── README.md
```

## Quick start (Windows / local development)

### 1. Backend

```powershell
cd "C:\Users\bmani\OneDrive\Desktop\ZeroTrace-Privacy-Analyzer\backend"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m spacy download en_core_web_sm
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py createsuperuser
.\.venv\Scripts\python.exe manage.py runserver 0.0.0.0:8000
```

If you want PostgreSQL locally, create a `.env` file in `backend/` with `DATABASE_URL=postgresql://user:password@localhost:5432/zerotrace` before running migrations.

### 2. Frontend

```powershell
cd "C:\Users\bmani\OneDrive\Desktop\ZeroTrace-Privacy-Analyzer\frontend"
npm install
npm run dev
```

Open `http://localhost:5173`. The Vite dev server proxies `/api` to `http://127.0.0.1:8000`.

### 3. Optional: Gitleaks

Download Gitleaks and either add it to `PATH` or set `GITLEAKS_BINARY` in `backend/.env` to the executable path. If Gitleaks is not present, repository scans still run real regex/entropy detection and the UI reports Gitleaks as not installed.

## Docker deployment

```powershell
cd "C:\Users\bmani\OneDrive\Desktop\ZeroTrace-Privacy-Analyzer"
Copy-Item backend\.env.example backend\.env
docker compose -f deployment/docker-compose.yml up --build
```

For local development after installing dependencies, `.\start-dev.ps1` launches both servers in separate windows.

Services: PostgreSQL, Django/Gunicorn backend on port 8000, nginx-served React build on port 3000. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for production hardening steps.

## Configuration

Create `backend/.env`:

```env
SECRET_KEY=replace-with-a-long-random-value
DEBUG=false
ALLOWED_HOSTS=localhost,127.0.0.1,your-domain.com
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
DATABASE_URL=postgresql://zerotrace:zerotrace@db:5432/zerotrace
GEMINI_API_KEY=
GEMINI_MODEL=gemini-1.5-flash
GITLEAKS_BINARY=gitleaks
DB_SSLMODE=prefer
```

`GEMINI_API_KEY` is optional; without it, the deterministic assessment engine is used even if the user has consented.

## API overview

Base URL: `/api/`

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/auth/register/` | Create account and receive token |
| POST | `/auth/login/` | Authenticate with email/password |
| POST | `/auth/logout/` | Revoke current token |
| GET | `/auth/me/` | Current user and consent state |
| POST | `/auth/consent/` | Enable/disable external AI consent |
| POST | `/scans/documents/` | Upload PDF/DOCX and scan |
| POST | `/scans/documents/batch/` | Scan up to 10 documents in one request |
| POST | `/scans/repositories/` | Scan explicitly authorized repository |
| GET | `/scans/` | List current user's scans |
| GET | `/scans/<uuid>/` | Scan detail with redacted findings |
| GET | `/scans/<uuid>/report/` | Download redacted PDF report |
| GET | `/dashboard/` | Aggregated dashboard metrics |
| GET | `/recommendations/` | Current user's remediation guidance |
| GET | `/findings/` | Redacted findings across scans |
| POST | `/findings/<id>/review/` | Mark a finding as false positive or restore it |
| POST | `/tools/sanitize/` | Download a metadata-clean PDF/DOCX copy |
| GET | `/audit/` | Privacy-safe account activity log |
| GET | `/health/` | Service and detector status |

Full request/response documentation is in [docs/API.md](docs/API.md).

## Testing

```powershell
cd backend
.\.venv\Scripts\python.exe manage.py test apps --verbosity 2

cd ..\frontend
npm run build
```

The suite covers auth/consent flows, document and batch upload, redaction, metadata sanitization, false-positive review, audit logging, PDF report generation, tenant isolation, authorized repository scanning, token fingerprinting, dashboard aggregation, detector rules, Luhn validation and risk scoring.

## Documentation

- [REST API documentation](docs/API.md)
- [Architecture and data-flow diagrams](docs/ARCHITECTURE.md)
- [Database ER diagram](docs/ER_DIAGRAM.md)
- [Deployment guide](docs/DEPLOYMENT.md)

## License

MIT © 2026 N.J.Bala Mani kantan — see [LICENSE](LICENSE).
