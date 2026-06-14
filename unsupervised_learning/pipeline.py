from __future__ import annotations

import logging
from typing import Dict, Iterable, Mapping

import pandas as pd

from anomaly_model import AnomalyDetector
from clustering_model import IPClusterer
from config import PipelineConfig
from feature_engineering import CLUSTER_FEATURE_COLUMNS, FEATURE_COLUMNS, FeatureEngineer
from realtime_firewall import RealtimeFirewallLogBuffer
from threat_fusion import ThreatSignalEmitter

logger = logging.getLogger(__name__)


class UnsupervisedPipeline:
    """Production-inspired training and inference pipeline for firewall logs."""

    def __init__(self, config: PipelineConfig | None = None):
        self.config = config or PipelineConfig()
        self.feature_engineer = FeatureEngineer(self.config)
        self.anomaly_model = AnomalyDetector(self.config)
        self.cluster_model = IPClusterer(self.config)
        self.fusion_engine = ThreatSignalEmitter(self.config)
        self.realtime_buffer = RealtimeFirewallLogBuffer(self.config)
        self._fitted = False
        self.training_validation_report: Dict[str, object] = {}
        self.last_validation_report: Dict[str, object] = {}

    def fit(self, train_df: pd.DataFrame) -> "UnsupervisedPipeline":
        """Train models on historical baseline logs only."""
        clean_df, validation = self.feature_engineer.validate_logs(train_df)
        self.training_validation_report = validation
        logger.info("Training validation report: %s", validation)

        anomaly_features = self.feature_engineer.build_anomaly_features(clean_df, validate=False)
        cluster_features = self.feature_engineer.build_cluster_features(clean_df, validate=False)

        self.anomaly_model.fit(anomaly_features, FEATURE_COLUMNS)
        self.cluster_model.fit(cluster_features, CLUSTER_FEATURE_COLUMNS)
        self._fitted = True
        return self

    def predict(self, test_df: pd.DataFrame) -> Dict[str, object]:
        """Score unseen firewall logs using previously fitted or loaded models."""
        if not self._fitted:
            raise RuntimeError("Pipeline is not trained. Run fit() or load_pipeline() before predict().")

        clean_df, validation = self.feature_engineer.validate_logs(test_df)
        self.last_validation_report = validation
        logger.info("Inference validation report: %s", validation)

        anomaly_features = self.feature_engineer.build_anomaly_features(clean_df, validate=False)
        cluster_features = self.feature_engineer.build_cluster_features(clean_df, validate=False)

        if anomaly_features.empty or cluster_features.empty:
            return {
                "anomaly_df": pd.DataFrame(),
                "cluster_df": pd.DataFrame(),
                "threat_signals": [],
                "validation_report": validation,
            }

        anomaly_results = self.anomaly_model.predict(anomaly_features)
        cluster_results = self.cluster_model.predict(cluster_features)
        signals = self.fusion_engine.emit(anomaly_results, cluster_results)

        return {
            "anomaly_df": anomaly_results,
            "cluster_df": cluster_results,
            "threat_signals": signals,
            "validation_report": validation,
        }

    def ingest_realtime(
        self,
        event: Mapping[str, object] | str,
        *,
        score_current_window: bool = True,
    ) -> Dict[str, object]:
        """Ingest one raw firewall event and score the active realtime window."""
        self.realtime_buffer.add(event)
        return self.predict_realtime(current_only=score_current_window)

    def predict_realtime(
        self,
        events: Iterable[Mapping[str, object] | str] | None = None,
        *,
        current_only: bool = True,
    ) -> Dict[str, object]:
        """
        Score live firewall logs from a rolling in-memory buffer.

        Events may be dictionaries, JSON-line strings, or common key=value
        syslog-style firewall records. By default only the latest timestamp
        window is scored, which avoids repeatedly alerting on stale buffered logs.
        """
        if events is not None:
            self.realtime_buffer.extend(events)

        live_df = self.realtime_buffer.to_frame(current_only=current_only)
        result = self.predict(live_df)
        result["threat_signals"] = self._filter_sparse_realtime_signals(result["threat_signals"])
        result["buffered_events"] = len(self.realtime_buffer)
        result["scored_events"] = int(len(live_df))
        return result

    def clear_realtime_buffer(self) -> None:
        self.realtime_buffer.clear()

    def _filter_sparse_realtime_signals(self, signals: list[dict]) -> list[dict]:
        min_events = int(self.config.realtime_min_events_per_ip)
        return [
            signal
            for signal in signals
            if int(signal.get("evidence", {}).get("total_events", 0)) >= min_events
        ]

    def run(self, raw_df: pd.DataFrame) -> Dict[str, object]:
        """
        Demo-only workflow: trains on raw_df and scores raw_df.

        Real deployments should call fit(historical_baseline) once, save_pipeline(),
        load_pipeline(), then predict(live_logs). This method is kept for FYP demos
        and backward compatibility.
        """
        logger.warning("run() trains and scores the same data. Use fit()+predict() to avoid leakage.")
        self.fit(raw_df)
        return self.predict(raw_df)

    def save_pipeline(self, anomaly_path: str | None = None, clustering_path: str | None = None) -> None:
        self.anomaly_model.save_model(anomaly_path)
        self.cluster_model.save_model(clustering_path)

    def load_pipeline(self, anomaly_path: str | None = None, clustering_path: str | None = None) -> "UnsupervisedPipeline":
        self.anomaly_model.load_model(anomaly_path)
        self.cluster_model.load_model(clustering_path)
        self._fitted = True
        return self

    def score_single(self, feature_dict: dict) -> dict:
        """Score one pre-aggregated anomaly feature vector."""
        if not self._fitted:
            raise RuntimeError("Pipeline is not trained. Run fit() or load_pipeline() first.")
        return self.anomaly_model.predict_single(feature_dict)
