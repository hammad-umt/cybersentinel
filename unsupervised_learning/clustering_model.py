from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

import joblib
import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN, KMeans
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler


class IPClusterer:
    """Profiles source-IP behavior with KMeans or DBSCAN clustering."""

    def __init__(self, config):
        self.config = config
        self.scaler = StandardScaler()
        self.kmeans = KMeans(
            n_clusters=config.kmeans_n_clusters,
            max_iter=config.kmeans_max_iter,
            n_init=10,
            random_state=config.random_state,
        )
        self.dbscan = DBSCAN(
            eps=config.dbscan_eps,
            min_samples=config.dbscan_min_samples,
            metric="euclidean",
        )
        self.feature_cols: List[str] = []
        self._distance_threshold = config.min_distance_threshold
        self._fitted = False
        self.metadata = {}
        self.clustering_algorithm = config.clustering_algorithm
        self._core_samples: np.ndarray | None = None
        self._core_labels: np.ndarray | None = None

    def fit(self, df: pd.DataFrame, feature_cols: List[str]) -> "IPClusterer":
        self._validate_training_frame(df, feature_cols)
        self.feature_cols = list(feature_cols)
        self.clustering_algorithm = self.config.clustering_algorithm

        X = self.scaler.fit_transform(df[self.feature_cols].astype(float))
        if self.clustering_algorithm == "dbscan":
            self._fit_dbscan(X)
        else:
            self._fit_kmeans(df, X)
        return self

    def predict(self, df: pd.DataFrame, feature_cols: List[str] | None = None) -> pd.DataFrame:
        if not self._fitted:
            raise RuntimeError("Cluster model is not trained. Run fit() or load_model() first.")

        cols = self.feature_cols if feature_cols is None else list(feature_cols)
        self._validate_inference_frame(df, cols)

        result = df.copy()
        X = self.scaler.transform(df[cols].astype(float))
        if self.metadata.get("clustering_algorithm", self.clustering_algorithm) == "dbscan":
            clusters, distances, outliers = self._predict_dbscan(X)
            result["kmeans_cluster"] = clusters
            result["cluster_distance"] = distances
            result["distance_outlier"] = outliers
            result["dbscan_cluster"] = clusters
        else:
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

    def _fit_kmeans(self, df: pd.DataFrame, X: np.ndarray) -> None:
        n_clusters = min(self.config.kmeans_n_clusters, len(df))
        if n_clusters != self.kmeans.n_clusters:
            self.kmeans = KMeans(
                n_clusters=n_clusters,
                max_iter=self.config.kmeans_max_iter,
                n_init=10,
                random_state=self.config.random_state,
            )
        self.kmeans.fit(X)
        labels = self.kmeans.labels_
        distances = np.linalg.norm(X - self.kmeans.cluster_centers_[labels], axis=1)
        self._distance_threshold = max(
            float(np.percentile(distances, self.config.cluster_distance_percentile)),
            float(self.config.min_distance_threshold),
        )
        self.metadata = {
            "model_version": self.config.model_version,
            "clustering_algorithm": "kmeans",
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_rows": int(len(df)),
            "feature_columns": self.feature_cols,
            "distance_threshold": self._distance_threshold,
        }
        self._fitted = True

    def _fit_dbscan(self, X: np.ndarray) -> None:
        labels = self.dbscan.fit_predict(X)
        core_mask = np.zeros(len(labels), dtype=bool)
        if self.dbscan.core_sample_indices_ is not None:
            core_mask[self.dbscan.core_sample_indices_] = True
        self._core_samples = X[core_mask]
        self._core_labels = labels[core_mask]
        self.metadata = {
            "model_version": self.config.model_version,
            "clustering_algorithm": "dbscan",
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_rows": int(len(X)),
            "feature_columns": self.feature_cols,
            "dbscan_eps": self.config.dbscan_eps,
            "dbscan_min_samples": self.config.dbscan_min_samples,
            "noise_ratio": float(np.mean(labels == -1)),
        }
        self._fitted = True

    def _predict_dbscan(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        if self._core_samples is None or len(self._core_samples) == 0:
            labels = np.full(len(X), -1, dtype=int)
            return labels, np.zeros(len(X)), np.ones(len(X), dtype=bool)

        neighbor = NearestNeighbors(n_neighbors=1)
        neighbor.fit(self._core_samples)
        distances, indices = neighbor.kneighbors(X)
        distances = distances.reshape(-1)
        assigned = self._core_labels[indices.reshape(-1)]
        within_eps = distances <= self.config.dbscan_eps
        labels = np.where(within_eps, assigned, -1)
        outliers = labels == -1
        return labels, distances, outliers

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
        payload = {
            "scaler": self.scaler,
            "feature_cols": self.feature_cols,
            "_distance_threshold": self._distance_threshold,
            "_fitted": self._fitted,
            "metadata": self.metadata,
            "clustering_algorithm": self.metadata.get("clustering_algorithm", self.clustering_algorithm),
        }
        if payload["clustering_algorithm"] == "dbscan":
            payload["dbscan"] = self.dbscan
            payload["_core_samples"] = self._core_samples
            payload["_core_labels"] = self._core_labels
        else:
            payload["kmeans"] = self.kmeans
        joblib.dump(payload, path)

    def load_model(self, filepath: str | None = None) -> "IPClusterer":
        state = joblib.load(filepath or self.config.clustering_model_path)
        self.scaler = state["scaler"]
        self.feature_cols = list(state.get("feature_cols", []))
        self._distance_threshold = float(state.get("_distance_threshold", self.config.min_distance_threshold))
        self._fitted = bool(state.get("_fitted", False))
        self.metadata = state.get("metadata", {})
        self.clustering_algorithm = state.get(
            "clustering_algorithm",
            self.metadata.get("clustering_algorithm", "kmeans"),
        )
        if self.clustering_algorithm == "dbscan":
            self.dbscan = state.get("dbscan", self.dbscan)
            self._core_samples = state.get("_core_samples")
            self._core_labels = state.get("_core_labels")
        else:
            self.kmeans = state["kmeans"]
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
