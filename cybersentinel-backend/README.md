# CyberSentinel Backend

FastAPI backend for the CyberSentinel FYP. It exposes packet classification,
live packet capture, firewall log analysis, threat intelligence enrichment,
unified threat scoring, SOC dashboard data, response action auditing, a
data-grounded Security Copilot, model health, alert history, and model reload
endpoints.

## Run Locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Open:

- API docs: http://localhost:8000/docs
- Health: http://localhost:8000/health
- SOC summary: http://localhost:8000/api/v1/dashboard/summary

If you bind the server to `0.0.0.0` for LAN/deployment access, still open it
in your browser using `http://localhost:8000` or `http://127.0.0.1:8000`.

Avoid running raw `uvicorn main:app --reload` from the backend root because it
can watch `.venv` and reload repeatedly while packages are imported. `run.py`
limits reload watching to the backend source folders.

## Important Model Paths

The default backend configuration expects this folder layout:

```text
ML Model/
  cybersentinel-backend/
  supervised_learning/models/
  unsupervised_learning/models/
```

The packet classifier loads cs-fyp XGBoost artifacts from `supervised_learning/models/`:

- `supervised_model.joblib`, `scaler.joblib`, `unsupervised_model.joblib`, `training_report.json`

Train with `python scripts/train_models.py` from the repo root.

Firewall analysis requires:

- `../unsupervised_learning/models/anomaly_model.joblib`
- `../unsupervised_learning/models/clustering_model.joblib`

If a model is missing, the backend still starts and `/health` reports which
model is unavailable. Endpoints that need that model return HTTP 503.

## Production Checklist

- Set `DEBUG=false`.
- Set exact frontend domains in `CORS_ORIGINS`.
- Set `ADMIN_API_KEY` before exposing `/api/v1/admin/reload-models`.
- Keep `RESPONSE_ACTION_EXECUTION_ENABLED=false` unless OS firewall execution
  has been reviewed and tested with administrator permissions.
- Use PostgreSQL for a multi-user deployment.
- Train and save both supervised and unsupervised models before demo/deploy.

## Security and Access Control

CyberSentinel uses **JWT Bearer authentication** (Sprint 3):

1. **Login** — `POST /api/v1/auth/token` with form fields `username` (your **email**) and `password`
2. **Use token** — `Authorization: Bearer <access_token>` on all `/api/v1/*` routes (except public auth routes)
3. **Swagger UI** — open http://localhost:8000/docs → call `POST /api/v1/auth/token` to get a token → click **Authorize** at the top → paste the `access_token`

Default admin on first startup: `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD` in `.env` (default `admin@cybersentinel.local` / `admin123`).

Public unauthenticated routes: `/`, `/health`, `/docs`, auth register/login/reset endpoints.

## Backend tests

Full test plan: [`tests/README.md`](tests/README.md)

```powershell
cd cybersentinel-backend
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

- **96+ automated test cases** with explicit pass/fail (fixed HTTP status codes)
- Runs on GitHub Actions (`.github/workflows/backend-tests.yml`)
- Uses in-memory SQLite + fake ML models — no Supabase or `.joblib` files required

## Database (Supabase)

Version 1.0 deployment uses **Supabase (managed PostgreSQL)**. Set in `.env`:

```env
DATABASE_URL=postgresql+asyncpg://postgres:PASSWORD@db.PROJECT.supabase.co:5432/postgres
```

The backend auto-converts `postgresql://` URLs from the Supabase dashboard to the async driver.
Tables (including `users` for JWT) are created automatically on startup.

SQLite (`sqlite+aiosqlite:///./cybersentinel.db`) remains supported for offline local dev only.

### Encrypt secrets at rest (one-time setup)

1. Put plain secrets in `.env` (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`,
   `ADMIN_API_KEY`, `ANALYST_API_KEY`).
2. Generate a Fernet master key: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
3. Set `CYBERSENTINEL_MASTER_KEY=<key>` in `.env`.
4. Run: `python -m core.secrets --encrypt`
5. Remove the plain secret values from `.env` (keep non-secret config). At startup
   the backend decrypts `secrets.enc` into memory.

Install `cryptography` from `requirements.txt` before encrypting.

## ML Training

Packet classification (cs-fyp XGBoost engine):

```powershell
# From repo root
python scripts/train_models.py --data supervised_learning/dataset --verbose
```

Artifacts: `supervised_model.joblib`, `unsupervised_model.joblib`, `scaler.joblib`, `training_report.json` in `supervised_learning/models/`.

Unsupervised firewall (`unsupervised_learning/train.py`):

```powershell
python train.py --log-path C:\path\to\pfirewall.log --clustering-algorithm kmeans
python train.py --log-path C:\path\to\pfirewall.log --clustering-algorithm dbscan
```

Firewall analysis accepts optional `clustering_algorithm=kmeans|dbscan`.

## Main API Areas

- `/api/v1/capture/*` - live Scapy/TShark packet metadata capture.
- `/api/v1/packet/*` - XGBoost packet/flow classification + SOC fusion.
- `/api/v1/packet/events.csv` - CSV export of packet events (same filters as JSON).
- `/api/v1/firewall/*` - uploaded and real-time firewall log analysis.
- `/api/v1/firewall/alerts.csv` - CSV export of firewall alerts (same filters as JSON).
- `/api/v1/firewall/intel/ip/{ip}` - AbuseIPDB, GeoIP (with ASN), and VirusTotal context.
- `/api/v1/intel/file` - VirusTotal file hash scan (multipart upload).
- `/api/v1/intel/url` - VirusTotal URL scan.
- `/api/v1/threat/*` - unified 0-100 threat scoring (`Low` / `Medium` / `High` / `Critical`).
- `/api/v1/capture/import` - offline PCAP import (`source=pcap_import` in packet events).
- `/api/v1/dashboard/summary` - SOC dashboard counters, geo distribution, and trend data.
- `/api/v1/response/actions` - response center action audit log.
- `/api/v1/copilot/ask` - investigation assistant over stored platform data.
- `/api/v1/reports/summary.pdf` - admin-gated SOC summary PDF (requires `X-Admin-Api-Key`).

## Severity Vocabulary

All API severity fields use `Low`, `Medium`, `High`, and `Critical`. Internal
firewall-pipeline labels (`Normal`, `Suspicious`, `Malicious-like`) are
translated at the API boundary; the database keeps the internal values.

## External API Retry Behavior

AbuseIPDB, GeoIP (`GEOIP_BASE_URL`), and VirusTotal HTTP calls retry up to
three times with exponential backoff (0.5s, 1s, 2s) on network errors and 5xx
responses. Client errors (4xx) are not retried.
