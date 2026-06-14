# CyberSentinel Backend

FastAPI backend for the CyberSentinel FYP. It exposes packet classification,
firewall log analysis, model health, alert history, and model reload endpoints.

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

The supervised route can load either the new
`packet_classifier_pipeline.joblib` bundle or the legacy
`packet_classifier.pkl`, `packet_scaler.pkl`, `packet_label_encoder.pkl`, and
`packet_features.pkl` artifacts.

Firewall analysis requires:

- `../unsupervised_learning/models/anomaly_model.joblib`
- `../unsupervised_learning/models/clustering_model.joblib`

If a model is missing, the backend still starts and `/health` reports which
model is unavailable. Endpoints that need that model return HTTP 503.

## Production Checklist

- Set `DEBUG=false`.
- Set exact frontend domains in `CORS_ORIGINS`.
- Set `ADMIN_API_KEY` before exposing `/api/v1/admin/reload-models`.
- Use PostgreSQL for a multi-user deployment.
- Train and save both supervised and unsupervised models before demo/deploy.
