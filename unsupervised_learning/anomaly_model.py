from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM


class AnomalyDetector:
    """Inductive anomaly detector for aggregated firewall behavior features."""

    def __init__(self, config):
        self.config = config
        self.scaler = StandardScaler()
        self.iforest = IsolationForest(
            n_estimators=config.if_n_estimators,
            contamination=config.if_contamination,
            random_state=config.random_state,
            n_jobs=-1,
        )
        self.ocsvm = (
            OneClassSVM(nu=config.ocsvm_nu, kernel=config.ocsvm_kernel, gamma="scale")
            if config.enable_ocsvm
            else None
        )
        self.feature_cols: List[str] = []
        self._fitted = False
        self._score_low = 0.0
        self._score_high = 1.0
        self.metadata = {}

    def fit(self, df: pd.DataFrame, feature_cols: List[str]) -> "AnomalyDetector":
        self._validate_training_frame(df, feature_cols)
        self.feature_cols = list(feature_cols)

        X = self.scaler.fit_transform(df[self.feature_cols].astype(float))
        self.iforest.fit(X)

        train_scores = self.iforest.score_samples(X)
        self._score_low = float(np.percentile(train_scores, 1))
        self._score_high = float(np.percentile(train_scores, 99))
        if self._score_high <= self._score_low:
            self._score_low = float(np.min(train_scores))
            self._score_high = float(np.max(train_scores))

        if self.ocsvm is not None:
            self.ocsvm.fit(X)

        self.metadata = {
            "model_version": self.config.model_version,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_rows": int(len(df)),
            "feature_columns": self.feature_cols,
            "score_calibration": {
                "low_percentile_score": self._score_low,
                "high_percentile_score": self._score_high,
            },
        }
        self._fitted = True
        return self

    def predict(self, df: pd.DataFrame, feature_cols: List[str] | None = None) -> pd.DataFrame:
        if not self._fitted:
            raise RuntimeError("Anomaly model is not trained. Run fit() or load_model() first.")

        cols = self.feature_cols if feature_cols is None else list(feature_cols)
        self._validate_inference_frame(df, cols)
        X = self.scaler.transform(df[cols].astype(float))

        raw_scores = self.iforest.score_samples(X)
        if_pred = self.iforest.predict(X)

        result = df.copy()
        result["anomaly_score"] = self._normalize(raw_scores)
        result["is_anomaly_if"] = if_pred == -1

        if self.ocsvm is not None:
            result["is_anomaly_ocsvm"] = self.ocsvm.predict(X) == -1
        else:
            result["is_anomaly_ocsvm"] = False

        result["consensus_anomaly"] = (
            result["is_anomaly_if"].astype(int) + result["is_anomaly_ocsvm"].astype(int)
        ) >= 1
        result["severity"] = result["anomaly_score"].map(self._severity)
        return result

    def predict_single(self, feature_dict: dict, feature_cols: List[str] | None = None) -> dict:
        return self.predict(pd.DataFrame([feature_dict]), feature_cols).iloc[0].to_dict()

    def _normalize(self, scores: np.ndarray) -> np.ndarray:
        if self._score_high <= self._score_low:
            return np.full(len(scores), 50.0)

        normality = (scores - self._score_low) / (self._score_high - self._score_low)
        normality = np.clip(normality, 0.0, 1.0)
        return (1.0 - normality) * 100.0

    def _severity(self, score: float) -> str:
        if score >= self.config.severity_critical:
            return "Critical"
        if score >= self.config.severity_malicious:
            return "Malicious-like"
        if score >= self.config.severity_suspicious:
            return "Suspicious"
        return "Normal"

    def save_model(self, filepath: str | None = None) -> None:
        if not self._fitted:
            raise RuntimeError("Refusing to save an unfitted anomaly model.")
        path = Path(filepath or self.config.anomaly_model_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "scaler": self.scaler,
                "iforest": self.iforest,
                "ocsvm": self.ocsvm,
                "feature_cols": self.feature_cols,
                "_fitted": self._fitted,
                "_score_low": self._score_low,
                "_score_high": self._score_high,
                "metadata": self.metadata,
            },
            path,
        )

    def load_model(self, filepath: str | None = None) -> "AnomalyDetector":
        state = joblib.load(filepath or self.config.anomaly_model_path)
        self.scaler = state["scaler"]
        self.iforest = state["iforest"]
        self.ocsvm = state["ocsvm"]
        self.feature_cols = list(state.get("feature_cols", []))
        self._fitted = bool(state["_fitted"])
        self._score_low = float(state["_score_low"])
        self._score_high = float(state["_score_high"])
        self.metadata = state.get("metadata", {})
        return self

    # Backward-compatible names used by older scripts.
    save = save_model
    load = load_model

    @staticmethod
    def _validate_training_frame(df: pd.DataFrame, feature_cols: List[str]) -> None:
        if df.empty:
            raise ValueError("No anomaly features extracted from training logs.")
        AnomalyDetector._validate_inference_frame(df, feature_cols)

    @staticmethod
    def _validate_inference_frame(df: pd.DataFrame, feature_cols: List[str]) -> None:
        missing = [col for col in feature_cols if col not in df.columns]
        if missing:
            raise ValueError(f"Missing anomaly feature columns: {missing}")
        if df[feature_cols].isna().any().any():
            raise ValueError("Anomaly features contain NaN values after preprocessing.")
