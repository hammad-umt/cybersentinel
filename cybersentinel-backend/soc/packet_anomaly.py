from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


DEFAULT_PACKET_ANOMALY_ARTIFACT = "packet_anomaly_isolation_forest.joblib"


@dataclass
class PacketAnomalyResult:
    packet_anomaly: bool
    packet_anomaly_score: float
    raw_score: float | None = None


class PacketIsolationForestDetector:
    """Isolation Forest detector for packet/flow anomalies only."""

    def __init__(
        self,
        features: list[str],
        pipeline: Pipeline | None = None,
        score_low: float = 0.0,
        score_high: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ):
        self.features = list(features)
        self.pipeline = pipeline
        self.score_low = float(score_low)
        self.score_high = float(score_high)
        self.metadata = metadata or {}

    def fit(
        self,
        flows: pd.DataFrame,
        *,
        contamination: float = 0.04,
        random_state: int = 42,
    ) -> "PacketIsolationForestDetector":
        model_module = _supervised_model_module()

        X = model_module.coerce_numeric_features(_prepare_frame(flows, self.features), self.features)
        self.pipeline = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
                (
                    "model",
                    IsolationForest(
                        n_estimators=300,
                        contamination=contamination,
                        random_state=random_state,
                        n_jobs=-1,
                    ),
                ),
            ]
        )
        self.pipeline.fit(X)
        model = self.pipeline.named_steps["model"]
        transformed = self.pipeline[:-1].transform(X)
        train_scores = model.score_samples(transformed)
        self.score_low = float(np.percentile(train_scores, 1))
        self.score_high = float(np.percentile(train_scores, 99))
        if self.score_high <= self.score_low:
            self.score_low = float(np.min(train_scores))
            self.score_high = float(np.max(train_scores))
        self.metadata = {
            "model": "IsolationForest",
            "purpose": "packet_flow_anomaly_detection",
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_rows": int(len(X)),
            "feature_columns": self.features,
            "contamination": contamination,
        }
        return self

    def predict(self, flows: pd.DataFrame) -> pd.DataFrame:
        if self.pipeline is None:
            raise RuntimeError("Packet anomaly detector is not loaded.")

        model_module = _supervised_model_module()

        X = model_module.coerce_numeric_features(_prepare_frame(flows, self.features), self.features)
        compatibility = model_module.assess_feature_coverage(X)
        model = self.pipeline.named_steps["model"]
        transformed = self.pipeline[:-1].transform(X)
        raw_scores = model.score_samples(transformed)
        labels = model.predict(transformed)
        anomaly_scores = self._normalize(raw_scores)

        result = pd.DataFrame(index=flows.index)
        result["packet_anomaly"] = labels == -1
        result["packet_anomaly_score"] = anomaly_scores
        result["packet_anomaly_raw_score"] = raw_scores
        result.loc[compatibility["feature_coverage"] < 0.65, "packet_anomaly"] = False
        result.loc[compatibility["feature_coverage"] < 0.65, "packet_anomaly_score"] = 0.0
        return result

    def predict_one(self, flows: pd.DataFrame) -> PacketAnomalyResult:
        row = self.predict(flows).iloc[0]
        return PacketAnomalyResult(
            packet_anomaly=bool(row["packet_anomaly"]),
            packet_anomaly_score=round(float(row["packet_anomaly_score"]), 2),
            raw_score=float(row["packet_anomaly_raw_score"]),
        )

    def save(self, path: str | Path) -> None:
        if self.pipeline is None:
            raise RuntimeError("Refusing to save an unfitted packet anomaly detector.")
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "features": self.features,
                "pipeline": self.pipeline,
                "score_low": self.score_low,
                "score_high": self.score_high,
                "metadata": self.metadata,
            },
            target,
        )

    @classmethod
    def load(cls, path: str | Path) -> "PacketIsolationForestDetector":
        state = joblib.load(path)
        return cls(
            features=list(state["features"]),
            pipeline=state["pipeline"],
            score_low=float(state["score_low"]),
            score_high=float(state["score_high"]),
            metadata=state.get("metadata", {}),
        )

    def _normalize(self, scores: np.ndarray) -> np.ndarray:
        if self.score_high <= self.score_low:
            return np.full(len(scores), 50.0)
        normality = (scores - self.score_low) / (self.score_high - self.score_low)
        normality = np.clip(normality, 0.0, 1.0)
        return (1.0 - normality) * 100.0


def _prepare_frame(flows: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    model_module = _supervised_model_module()

    normalized = model_module.normalize_columns(flows.copy())
    normalized = model_module.standardize_live_flow_features(normalized)
    for feature in features:
        if feature not in normalized.columns:
            normalized[feature] = np.nan
    return normalized


def _supervised_model_module():
    try:
        from supervised_learning import model as supervised_model
    except ModuleNotFoundError:
        import model as supervised_model
    return supervised_model
