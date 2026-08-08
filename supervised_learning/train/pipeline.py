"""Train XGBoost + Isolation Forest and save artifacts for the CyberSentinel backend."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Optional

import numpy as np

from supervised_learning.train._features import ATTACK_CLASSES
from supervised_learning.train.metrics import evaluate_supervised, evaluate_unsupervised
from supervised_learning.train.preprocessing import preprocess_cicids

logger = logging.getLogger(__name__)


def train_supervised(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    class_weights: Dict[int, float],
    models_dir: Path,
) -> Dict:
    import joblib

    models_dir.mkdir(parents=True, exist_ok=True)

    sample_weights = np.array([class_weights.get(int(y), 1.0) for y in y_train])
    model = None
    model_type = "xgboost"

    try:
        import xgboost as xgb

        model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            objective="multi:softprob",
            eval_metric="mlogloss",
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_train, y_train, sample_weight=sample_weights)
        model_type = "xgboost"
        logger.info("Trained XGBoost supervised model")
    except ImportError as exc:
        raise ImportError(
            "xgboost is required to train the packet classifier. Install with: pip install xgboost"
        ) from exc

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None

    joblib.dump(model, models_dir / "supervised_model.joblib")

    metrics = evaluate_supervised(y_test, y_pred, y_proba, ATTACK_CLASSES)
    metrics["model_type"] = model_type

    bin_metrics = metrics["binary_attack_detection"]
    logger.info(
        "Supervised — Acc: %.4f | F1: %.4f | FPR: %.4f | FNR: %.4f",
        metrics["accuracy"],
        metrics["f1_macro"],
        bin_metrics["false_positive_rate"],
        bin_metrics["false_negative_rate"],
    )
    return metrics


def train_unsupervised(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    models_dir: Path,
    contamination: Optional[float] = None,
) -> Dict:
    import joblib
    from sklearn.ensemble import IsolationForest

    models_dir.mkdir(parents=True, exist_ok=True)

    benign_mask = y_train == 0
    X_benign = X_train[benign_mask]

    if len(X_benign) < 100:
        logger.warning("Few benign samples (%d) — using full train set for IF", len(X_benign))
        X_benign = X_train

    if contamination is None:
        attack_rate = float((y_train != 0).sum()) / len(y_train)
        contamination = max(0.01, min(attack_rate, 0.15))

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_benign)

    anomaly_pred = model.predict(X_test) == -1
    raw_scores = model.decision_function(X_test)
    anomaly_scores = 1.0 / (1.0 + np.exp(raw_scores * 2))

    eval_metrics = evaluate_unsupervised(y_test, anomaly_pred, anomaly_scores)

    metrics = {
        "model_type": "isolation_forest",
        "trained_on_benign_samples": len(X_benign),
        "contamination": contamination,
        **eval_metrics,
    }

    joblib.dump(model, models_dir / "unsupervised_model.joblib")
    logger.info(
        "Unsupervised — FPR: %.4f | FNR: %.4f",
        eval_metrics["false_positive_rate"],
        eval_metrics["false_negative_rate"],
    )
    return metrics


def train_from_dataset(
    data_path: Path,
    processed_dir: Path,
    models_dir: Path,
    benign_max_ratio: float = 3.0,
) -> Dict:
    """Preprocess CICIDS data, train both models, save to models_dir (backend loads from here)."""
    artifacts = preprocess_cicids(
        data_path=data_path,
        output_dir=processed_dir,
        benign_max_ratio=benign_max_ratio,
    )

    supervised_metrics = train_supervised(
        artifacts["X_train"],
        artifacts["y_train"],
        artifacts["X_test"],
        artifacts["y_test"],
        artifacts["class_weights"],
        models_dir,
    )

    unsupervised_metrics = train_unsupervised(
        artifacts["X_train"],
        artifacts["y_train"],
        artifacts["X_test"],
        artifacts["y_test"],
        models_dir,
    )

    import joblib

    joblib.dump(artifacts["scaler"], models_dir / "scaler.joblib")

    report = {
        "supervised": supervised_metrics,
        "unsupervised": unsupervised_metrics,
        "preprocessing": artifacts["metadata"],
    }

    with open(models_dir / "training_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info("Training complete — models saved to %s", models_dir)
    return report
