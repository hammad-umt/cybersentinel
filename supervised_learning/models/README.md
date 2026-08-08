# Supervised ML model artifacts (CyberSentinel backend)

Training writes XGBoost + Isolation Forest artifacts here. The backend loads them automatically at startup.

## Train models

From the **CyberSentinel repo root** (`Desktop\cybersentinel`):

```powershell
# Install deps once (backend venv)
cd cybersentinel-backend
.\venv\Scripts\pip install -r requirements.txt

# Train (uses CICIDS CSVs in supervised_learning/dataset/)
cd ..
.\scripts\train_models.ps1 --verbose
```

Or:

```powershell
python scripts/train_models.py --data supervised_learning/dataset --verbose
```

## Output files

| File | Purpose |
|------|---------|
| `supervised_model.joblib` | XGBoost 7-class classifier |
| `unsupervised_model.joblib` | Isolation Forest anomaly detector |
| `scaler.joblib` | StandardScaler (shared) |
| `training_report.json` | Accuracy, F1, AUC, FPR, FNR, confusion matrix |

## Reload without restart

`POST /api/v1/admin/reload-models` (Administrator JWT)

Or view metrics: `GET /api/v1/training/metrics`

## Dataset

Place CICIDS2017 CSV files in `supervised_learning/dataset/`. Eight files are already included in this project.
