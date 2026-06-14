from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

import joblib
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler


class IPClusterer:
    """Profiles source-IP behavior and flags hosts far from baseline clusters."""

    def __init__(self, config):
        self.config = config
        self.scaler = StandardScaler()
        self.kmeans = KMeans(
            n_clusters=config.kmeans_n_clusters,
            max_iter=config.kmeans_max_iter,
            n_init=10,
            random_state=config.random_state,
        )
        self.feature_cols: List[str] = []
        self._distance_threshold = config.min_distance_threshold
        self._fitted = False
        self.metadata = {}

    def fit(self, df: pd.DataFrame, feature_cols: List[str]) -> "IPClusterer":
        self._validate_training_frame(df, feature_cols)
        self.feature_cols = list(feature_cols)

        n_clusters = min(self.config.kmeans_n_clusters, len(df))
        if n_clusters != self.kmeans.n_clusters:
            self.kmeans = KMeans(
                n_clusters=n_clusters,
                max_iter=self.config.kmeans_max_iter,
                n_init=10,
                random_state=self.config.random_state,
            )

        X = self.scaler.fit_transform(df[self.feature_cols].astype(float))
        self.kmeans.fit(X)

        labels = self.kmeans.labels_
        distances = np.linalg.norm(X - self.kmeans.cluster_centers_[labels], axis=1)
        self._distance_threshold = max(
            float(np.percentile(distances, self.config.cluster_distance_percentile)),
            float(self.config.min_distance_threshold),
        )
        self.metadata = {
            "model_version": self.config.model_version,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_rows": int(len(df)),
            "feature_columns": self.feature_cols,
            "distance_threshold": self._distance_threshold,
        }
        self._fitted = True
        return self

    def predict(self, df: pd.DataFrame, feature_cols: List[str] | None = None) -> pd.DataFrame:
        if not self._fitted:
            raise RuntimeError("Cluster model is not trained. Run fit() or load_model() first.")

        cols = self.feature_cols if feature_cols is None else list(feature_cols)
        self._validate_inference_frame(df, cols)

        result = df.copy()
        X = self.scaler.transform(df[cols].astype(float))
        clusters = self.kmeans.predict(X)
        distances = np.linalg.norm(X - self.kmeans.cluster_centers_[clusters], axis=1)

        result["kmeans_cluster"] = clusters
        result["cluster_distance"] = distances
        result["distance_outlier"] = distances > self._distance_threshold
        result["dbscan_cluster"] = np.where(result["distance_outlier"], -1, clusters)
        result["attack_signal_count"] = self._attack_signal_count(result)
        result["cluster_interpretation"] = np.select(
            [
                result["attack_signal_count"] >= 3,
                result["distance_outlier"] & (result["attack_signal_count"] >= 1),
                result["distance_outlier"],
                result["attack_signal_count"] >= 1,
            ],
            ["Attack", "Attack", "Isolated", "Suspicious"],
            default="Normal",
        )
        return result

    def predict_single(self, feature_dict: dict, feature_cols: List[str] | None = None) -> dict:
        return self.predict(pd.DataFrame([feature_dict]), feature_cols).iloc[0].to_dict()

    def _attack_signal_count(self, df: pd.DataFrame) -> pd.Series:
        signals = pd.DataFrame(index=df.index)
        signals["high_block_ratio"] = df.get("block_ratio", 0) >= self.config.block_ratio
        signals["many_ports"] = df.get("unique_ports", 0) >= self.config.port_scan_unique_ports
        signals["port_scan"] = df.get("port_scan_score", 0) >= self.config.port_scan_score
        signals["off_hours"] = df.get("off_hours_ratio", 0) >= self.config.off_hours_ratio
        signals["burst"] = df.get("burst_index", 0) >= self.config.burst_index
        signals["many_destinations"] = df.get("dst_ip_diversity", 0) >= self.config.destination_diversity
        signals["brute_force_like"] = df.get("blocked_events", 0) >= self.config.brute_force_block_count
        return signals.astype(int).sum(axis=1)

    def save_model(self, filepath: str | None = None) -> None:
        if not self._fitted:
            raise RuntimeError("Refusing to save an unfitted cluster model.")
        path = Path(filepath or self.config.clustering_model_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "scaler": self.scaler,
                "kmeans": self.kmeans,
                "feature_cols": self.feature_cols,
                "_distance_threshold": self._distance_threshold,
                "_fitted": self._fitted,
                "metadata": self.metadata,
            },
            path,
        )

    def load_model(self, filepath: str | None = None) -> "IPClusterer":
        state = joblib.load(filepath or self.config.clustering_model_path)
        self.scaler = state["scaler"]
        self.kmeans = state["kmeans"]
        self.feature_cols = list(state.get("feature_cols", []))
        self._distance_threshold = float(state["_distance_threshold"])
        self._fitted = bool(state["_fitted"])
        self.metadata = state.get("metadata", {})
        return self

    save = save_model
    load = load_model

    @staticmethod
    def _validate_training_frame(df: pd.DataFrame, feature_cols: List[str]) -> None:
        if df.empty:
            raise ValueError("No cluster features extracted from training logs.")
        IPClusterer._validate_inference_frame(df, feature_cols)

    @staticmethod
    def _validate_inference_frame(df: pd.DataFrame, feature_cols: List[str]) -> None:
        missing = [col for col in feature_cols if col not in df.columns]
        if missing:
            raise ValueError(f"Missing cluster feature columns: {missing}")
        if df[feature_cols].isna().any().any():
            raise ValueError("Cluster features contain NaN values after preprocessing.")
