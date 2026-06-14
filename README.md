# CyberSentinel ML Model

CyberSentinel is an FYP cybersecurity backend and ML workspace. It contains:

- `cybersentinel-backend/` - FastAPI backend, routers, schemas, services, database models, and app launcher.
- `supervised_learning/` - CICIDS-style packet classification training and inference code.
- `unsupervised_learning/` - Firewall log anomaly detection, clustering, realtime buffering, and threat fusion code.

## Backend Quick Start

```powershell
cd cybersentinel-backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Open:

- http://127.0.0.1:8000/
- http://127.0.0.1:8000/docs
- http://127.0.0.1:8000/health

## Repository Notes

Large datasets, local databases, virtual environments, `.env`, and generated model binaries are intentionally ignored by Git. Keep `.env.example` committed as the template.

To reproduce model artifacts:

- Supervised: train using `supervised_learning/model.py`.
- Unsupervised: train using `unsupervised_learning/train.py`.

If trained artifacts are needed in deployment, store them outside GitHub or use Git LFS/release assets.
