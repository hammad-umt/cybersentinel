"""
XGBoost packet classifier — drop-in replacement for CyberSentinelPacketClassifier.

Exposes predict(flows: DataFrame) → DataFrame with Flutter-compatible columns:
  prediction, confidence, prob_Normal, prob_Suspicious, prob_Malicious,
  feature_coverage, missing_feature_count, traffic_schema
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from loguru import logger

from ml_engine.column_mapping import flows_to_feature_matrix, load_training_report
from ml_engine.features import (
    ATTACK_CLASSES,
    ATTACK_TO_FLUTTER,
    DEGRADED_FEATURE_COVERAGE,
    FLUTTER_CLASSES,
    INSUFFICIENT_EVIDENCE_LABEL,
    MIN_PRODUCTION_FEATURE_COVERAGE,
    MODEL_TO_PUBLIC_ATTACK,
)


@dataclass
class TrainingReportView:
    accuracy: float | None = None
    f1_weighted: float | None = None
    classes: list[str] | None = None


class CyberSentinelXGBClassifier:
    """Loads cs-fyp XGBoost artifacts and predicts Normal/Suspicious/Malicious."""

    def __init__(self, model_dir: Path, benign_threshold: float = 0.55):
        self.model_dir = Path(model_dir)
        self.model = joblib.load(self.model_dir / "supervised_model.joblib")
        self.scaler = joblib.load(self.model_dir / "scaler.joblib")
        self.benign_threshold = benign_threshold
        self.training_report_raw = load_training_report(self.model_dir)
        sup = self.training_report_raw.get("supervised", {})
        self.training_report = TrainingReportView(
            accuracy=sup.get("accuracy"),
            f1_weighted=sup.get("f1_weighted"),
            classes=list(FLUTTER_CLASSES),
        )
        logger.info("XGBoost classifier loaded from {}", self.model_dir)

    @classmethod
    def load_model(cls, model_dir: str | Path, model_type: str = "xgboost") -> "CyberSentinelXGBClassifier":
        return cls(Path(model_dir))

    def predict(self, flows: pd.DataFrame) -> pd.DataFrame:
        X, compatibility = flows_to_feature_matrix(flows)
        X_scaled = self.scaler.transform(X)

        if hasattr(self.model, "predict_proba"):
            proba_7 = self.model.predict_proba(X_scaled)
            class_indices = {int(c): i for i, c in enumerate(self.model.classes_)}
        else:
            preds = self.model.predict(X_scaled)
            proba_7 = np.zeros((len(X), len(ATTACK_CLASSES)))
            for i, p in enumerate(preds):
                idx = int(p) if int(p) < len(ATTACK_CLASSES) else 0
                proba_7[i, idx] = 1.0
            class_indices = {i: i for i in range(len(ATTACK_CLASSES))}

        n = len(flows)
        prob_normal = np.zeros(n)
        prob_suspicious = np.zeros(n)
        prob_malicious = np.zeros(n)

        for attack_name, flutter_label in ATTACK_TO_FLUTTER.items():
            if attack_name not in ATTACK_CLASSES:
                continue
            idx = ATTACK_CLASSES.index(attack_name)
            col = class_indices.get(idx, idx)
            if col >= proba_7.shape[1]:
                continue
            column = proba_7[:, col]
            if flutter_label == "Normal":
                prob_normal += column
            elif flutter_label == "Suspicious":
                prob_suspicious += column
            else:
                prob_malicious += column

        predictions = []
        confidences = []
        raw_model_predictions = []
        raw_confidences = []
        for i in range(n):
            # Granular 7-class argmax
            best_idx = int(np.argmax(proba_7[i]))
            raw_class = ATTACK_CLASSES[best_idx] if best_idx < len(ATTACK_CLASSES) else "Benign"
            raw_public = MODEL_TO_PUBLIC_ATTACK.get(raw_class, raw_class)
            raw_conf = float(proba_7[i, best_idx]) if best_idx < proba_7.shape[1] else 0.0
            raw_model_predictions.append(raw_public)
            raw_confidences.append(raw_conf)

            if prob_normal[i] >= self.benign_threshold:
                predictions.append("Normal")
                confidences.append(float(prob_normal[i]))
            else:
                flutter_probs = {
                    "Normal": prob_normal[i],
                    "Suspicious": prob_suspicious[i],
                    "Malicious": prob_malicious[i],
                }
                best = max(flutter_probs, key=flutter_probs.get)
                predictions.append(best)
                confidences.append(float(flutter_probs[best]))

        result = pd.DataFrame(
            {
                "prediction": predictions,
                "confidence": confidences,
                "raw_model_prediction": raw_model_predictions,
                "raw_model_confidence": raw_confidences,
                "prob_Normal": prob_normal,
                "prob_Suspicious": prob_suspicious,
                "prob_Malicious": prob_malicious,
            },
            index=flows.index,
        )

        insufficient = compatibility["feature_coverage"] < MIN_PRODUCTION_FEATURE_COVERAGE
        degraded = (compatibility["feature_coverage"] >= MIN_PRODUCTION_FEATURE_COVERAGE) & (
            compatibility["feature_coverage"] < DEGRADED_FEATURE_COVERAGE
        )
        result.loc[insufficient, "prediction"] = INSUFFICIENT_EVIDENCE_LABEL
        result.loc[insufficient, "confidence"] = 0.0
        result.loc[insufficient, "raw_model_prediction"] = INSUFFICIENT_EVIDENCE_LABEL
        result.loc[insufficient, "raw_model_confidence"] = 0.0
        result.loc[degraded, "confidence"] = (
            result.loc[degraded, "confidence"] * compatibility.loc[degraded, "feature_coverage"]
        )

        for col in ("feature_coverage", "missing_feature_count", "missing_features", "traffic_schema"):
            result[col] = compatibility[col]

        return result


class XGBPacketAnomalyDetector:
    """Isolation Forest from cs-fyp — same predict() interface as PacketIsolationForestDetector."""

    def __init__(self, model_dir: Path):
        self.model_dir = Path(model_dir)
        self.model = joblib.load(self.model_dir / "unsupervised_model.joblib")
        self.scaler = joblib.load(self.model_dir / "scaler.joblib")
        self.metadata = {"model": "IsolationForest", "source": "cs-fyp_xgboost_engine"}

    @classmethod
    def load(cls, path: str | Path) -> "XGBPacketAnomalyDetector":
        return cls(Path(path).parent if Path(path).is_file() else Path(path))

    def predict(self, flows: pd.DataFrame) -> pd.DataFrame:
        X, compatibility = flows_to_feature_matrix(flows)
        X_scaled = self.scaler.transform(X)
        labels = self.model.predict(X_scaled)
        raw_scores = self.model.decision_function(X_scaled)
        anomaly_scores = 1.0 / (1.0 + np.exp(raw_scores * 2))
        anomaly_scores = anomaly_scores * 100.0

        result = pd.DataFrame(index=flows.index)
        result["packet_anomaly"] = labels == -1
        result["packet_anomaly_score"] = anomaly_scores
        result["packet_anomaly_raw_score"] = raw_scores
        low_cov = compatibility["feature_coverage"] < MIN_PRODUCTION_FEATURE_COVERAGE
        result.loc[low_cov, "packet_anomaly"] = False
        result.loc[low_cov, "packet_anomaly_score"] = 0.0
        return result
