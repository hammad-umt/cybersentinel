"""ML training metrics API — does not affect Flutter contracts."""

import json

from fastapi import APIRouter, Depends, HTTPException

from core.config import settings
from core.security import require_role

router = APIRouter(prefix="/api/v1/training", tags=["Training"])


@router.get(
    "/metrics",
    summary="ML evaluation metrics (XGBoost)",
    description="Returns training_report.json: accuracy, F1, AUC, FPR, FNR, confusion matrix.",
)
async def training_metrics(_user=Depends(require_role("admin"))):
    report_path = settings.training_report_path
    if not report_path.exists():
        raise HTTPException(
            status_code=404,
            detail="No training report found. Run scripts/train_models.py from the CyberSentinel repo root.",
        )
    with open(report_path, encoding="utf-8") as f:
        return json.load(f)


@router.get(
    "/status",
    summary="ML model file status",
)
async def training_status(_user=Depends(require_role("admin"))):
    model_dir = settings.SUPERVISED_MODEL_DIR
    status = {
        "model_dir": str(model_dir),
        "xgboost_supervised": settings.xgboost_supervised_path.exists(),
        "xgboost_unsupervised": settings.xgboost_unsupervised_path.exists(),
        "scaler": settings.xgboost_scaler_path.exists(),
        "training_report": settings.training_report_path.exists(),
    }
    if settings.training_report_path.exists():
        with open(settings.training_report_path, encoding="utf-8") as f:
            status["metrics_summary"] = json.load(f).get("supervised", {})
    return status
