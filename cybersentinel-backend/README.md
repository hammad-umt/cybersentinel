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

## Security and Access Control

All `/api/v1/*` routes require a valid API key header:

- `X-Admin-Api-Key` — full read/write access
- `X-Analyst-Api-Key` — read-only (GET/HEAD/OPTIONS only)

Public unauthenticated routes: `/`, `/health`, `/docs`, `/redoc`, `/openapi.json`.

Admin-only write routes include capture start/stop, PCAP import, firewall monitor
controls, response action creation, alert acknowledgement, model reload, and PDF
reports.

### Encrypt secrets at rest (one-time setup)

1. Put plain secrets in `.env` (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`,
   `ADMIN_API_KEY`, `ANALYST_API_KEY`).
2. Generate a Fernet master key: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
3. Set `CYBERSENTINEL_MASTER_KEY=<key>` in `.env`.
4. Run: `python -m core.secrets --encrypt`
5. Remove the plain secret values from `.env` (keep non-secret config). At startup
   the backend decrypts `secrets.enc` into memory.

Install `cryptography` from `requirements.txt` before encrypting.

## ML Training Options

Supervised (`supervised_learning/model.py`):

```powershell
python model.py --data_path ./dataset --model_type random_forest
python model.py --data_path ./dataset/unsw --dataset_type unsw-nb15 --model_type svm
python model.py --data_path ./dataset --dataset_type both --model_type decision_tree
```

Artifacts are saved as `packet_classifier_pipeline.{model_type}.joblib`. Inference
accepts optional `model_type` on `POST /api/v1/packet/classify` and batch upload.

Unsupervised (`unsupervised_learning/train.py`):

```powershell
python train.py --log-path C:\path\to\pfirewall.log --clustering-algorithm kmeans
python train.py --log-path C:\path\to\pfirewall.log --clustering-algorithm dbscan
```

Firewall analysis accepts optional `clustering_algorithm=kmeans|dbscan`.

## Main API Areas

- `/api/v1/capture/*` - live Scapy/TShark packet metadata capture.
- `/api/v1/packet/*` - supervised Random Forest packet/flow classification.
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
