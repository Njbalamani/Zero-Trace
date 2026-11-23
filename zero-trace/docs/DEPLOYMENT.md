# Deployment Guide

## Option A: Docker Compose (recommended)

The provided stack starts PostgreSQL, the Django API behind Gunicorn, and an nginx container serving the production React bundle.

```powershell
cd ZeroTrace-Privacy-Analyzer
docker compose -f deployment/docker-compose.yml up --build -d
```

Services:

| Service | Port | Description |
| --- | --- | --- |
| `db` | 5432 (internal) | PostgreSQL 16 |
| `backend` | 8000 (internal) | Django + Gunicorn, migrations applied on start |
| `frontend` | 3000 | nginx serving `frontend/dist` and proxying `/api` |

Create `backend/.env` before starting:

```env
SECRET_KEY=replace-with-a-long-random-secret
DEBUG=false
ALLOWED_HOSTS=localhost,127.0.0.1,backend
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
DATABASE_URL=postgresql://zerotrace:zerotrace@db:5432/zerotrace
DB_SSLMODE=prefer
GEMINI_API_KEY=
GITLEAKS_BINARY=gitleaks
```

Stop the stack:

```powershell
docker compose -f deployment/docker-compose.yml down
```

## Option B: Manual production deployment

### PostgreSQL

```sql
CREATE USER zerotrace WITH PASSWORD 'replace-me';
CREATE DATABASE zerotrace OWNER zerotrace;
```

Set `DATABASE_URL=postgresql://zerotrace:replace-me@localhost:5432/zerotrace` in `backend/.env`.

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python manage.py migrate
python manage.py collectstatic --noinput
python manage.py check --deploy
gunicorn zerotrace.wsgi:application --bind 127.0.0.1:8000 --workers 3
```

### Frontend

```bash
cd frontend
npm install
npm run build
```

Serve `frontend/dist` with nginx using `deployment/nginx.conf`, proxying `/api` to Gunicorn. A sample configuration is included.

### Environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `SECRET_KEY` | Django signing key | insecure dev value — must override |
| `DEBUG` | Debug mode | `true` |
| `ALLOWED_HOSTS` | Comma-separated hosts | localhost,127.0.0.1 |
| `CORS_ALLOWED_ORIGINS` | Allowed SPA origins | localhost:5173/3000 |
| `DATABASE_URL` | PostgreSQL connection string | unset (SQLite fallback) |
| `DB_SSLMODE` | PostgreSQL SSL mode | prefer |
| `GEMINI_API_KEY` | Optional external AI key | unset |
| `GEMINI_MODEL` | Gemini model name | gemini-1.5-flash |
| `GITLEAKS_BINARY` | Gitleaks executable name/path | gitleaks |
| `GITLEAKS_TIMEOUT` | Seconds per Gitleaks run | 120 |
| `GITHUB_TIMEOUT` | GitHub HTTP timeout | 30 |
| `MAX_REPO_FILES` | Max files scanned per repo | 400 |
| `MAX_REPO_FILE_BYTES` | Max bytes per repo file | 512000 |
| `SPACY_MODEL` | spaCy NER model | en_core_web_sm |

## Gitleaks

Install the Gitleaks binary and make it available on `PATH`, or set `GITLEAKS_BINARY` to its absolute path. The backend invokes `gitleaks detect --redact --no-git` against a temporary directory containing authorized repository files, then removes the directory. If the binary is unavailable, repository scans continue with regex/entropy detection and report `gitleaks_available: false`.

## Security checklist

- Set `DEBUG=false` and a strong random `SECRET_KEY`.
- Restrict `ALLOWED_HOSTS` and `CORS_ALLOWED_ORIGINS`.
- Terminate TLS at nginx or a load balancer; set `SECURE_SSL_REDIRECT=true` when appropriate.
- Run the application behind a reverse proxy with request size limits.
- Use a dedicated PostgreSQL role with least privilege.
- Keep `GEMINI_API_KEY` empty unless explicit user consent handling is reviewed.
- Monitor logs for repeated `401`/`403` GitHub messages and API throttling.
- Apply OS and Python package updates regularly.
- Back up PostgreSQL; uploaded files do not require backup because they are never persisted.

## Health check

```bash
curl http://127.0.0.1:8000/api/health/
```

Expected response includes `"status": "ok"` and detector information.

## Verification

```bash
python manage.py test apps --verbosity 2
python manage.py check --deploy
cd ../frontend && npm run build
```
