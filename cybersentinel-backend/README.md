# CyberSentinel Backend

This directory contains the FastAPI backend for CyberSentinel. It provides the API layer for packet analysis, live capture, firewall log inspection, threat intelligence enrichment, dashboard summaries, response auditing, and the security copilot experience.

## What the backend does

The backend is responsible for:

- ingesting and processing packet and flow data
- running ML-based classification and threat scoring
- analyzing firewall logs and surfacing suspicious activity
- enriching events with external intelligence sources
- serving authenticated dashboard and reporting endpoints
- exposing a REST API for the frontend and desktop client

## Technology stack

- Python 3.12+
- FastAPI
- Uvicorn
- SQLAlchemy + async database support
- Pydantic and Pydantic Settings
- Scapy for packet capture
- XGBoost, scikit-learn, pandas, numpy, joblib for ML
- pytest for automated testing

## Project structure

- app entry points: `run.py`, `main.py`, `engine_main.py`
- API routes: `routers/`
- business logic and integrations: `services/`
- database models and session handling: `db/`
- configuration and security helpers: `core/`
- request/response schemas: `schemas/`
- tests: `tests/`
- model training scripts: `scripts/`

## Prerequisites

Before running the backend, make sure you have:

- Python 3.12 installed
- A virtual environment created for the project
- Optional Windows tools for live capture:
  - Npcap
  - Wireshark / TShark

## Local setup

From the backend folder, run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

The server will start locally and expose:

- API docs: http://localhost:8000/docs
- Health check: http://localhost:8000/health
- Dashboard summary: http://localhost:8000/api/v1/dashboard/summary

> Use `python run.py` instead of running raw `uvicorn` from the backend root. The launcher limits reload watching to the relevant backend source folders and avoids unnecessary reload loops.

## Configuration

The backend uses environment variables from `.env`. Configure values such as:

- `DATABASE_URL`
- `SECRET_KEY` or equivalent auth settings
- `CORS_ORIGINS`
- `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD`
- API keys for VirusTotal, AbuseIPDB, and related services

For local development, SQLite is supported for convenience. For production or multi-user deployment, PostgreSQL/Supabase is recommended.

## Authentication

The API uses JWT-based authentication. Typical flow:

1. Call `POST /api/v1/auth/token` with your email and password.
2. Copy the returned access token.
3. Add it as a Bearer token in the Swagger UI Authorize dialog.

Public routes include health and authentication endpoints. Protected API routes require a valid token.

## Testing

Run the backend test suite with:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

The test suite includes automated checks for auth, API protection, services, and routing behavior.

## Model training

The backend expects trained ML artifacts for packet classification and anomaly detection. From the repository root, you can train the models with:

```powershell
python scripts/train_models.py
```

The training process generates model files under the learning workspace directories. If a required model is missing, the backend can still start, but endpoints that depend on that model may return HTTP 503.

## Production checklist

Before deploying the backend, confirm that:

- `DEBUG` is disabled in production
- allowed frontend origins are explicitly configured
- admin API keys are set before exposing admin-only routes
- response execution is disabled unless reviewed and approved
- PostgreSQL is used for multi-user environments
- the necessary ML models are trained and available

## Notes

- Do not commit secrets or local environment files.
- Keep `.env` local and private.
- Use the Swagger UI at `/docs` to explore the available endpoints during development.
