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
- Keep `RESPONSE_ACTION_EXECUTION_ENABLED=false` unless OS firewall execution
  has been reviewed and tested with administrator permissions.
- Use PostgreSQL for a multi-user deployment.
- Train and save both supervised and unsupervised models before demo/deploy.

## Main API Areas

- `/api/v1/capture/*` - live Scapy/TShark packet metadata capture.
- `/api/v1/packet/*` - supervised Random Forest packet/flow classification.
- `/api/v1/firewall/*` - uploaded and real-time firewall log analysis.
- `/api/v1/firewall/intel/ip/{ip}` - AbuseIPDB, GeoIP, and VirusTotal context.
- `/api/v1/threat/*` - unified 0-100 threat scoring.
- `/api/v1/dashboard/summary` - SOC dashboard counters and recent alerts.
- `/api/v1/response/actions` - response center action audit log.
- `/api/v1/copilot/ask` - investigation assistant over stored platform data.
