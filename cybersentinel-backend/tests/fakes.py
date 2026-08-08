"""Deterministic ML fakes for CI — no model files or GPU required."""

from __future__ import annotations

import pandas as pd

from models.loader import DEFAULT_CLUSTERING_ALGORITHM, DEFAULT_PACKET_MODEL_TYPE, ModelRegistry


class FakePacketClassifier:
    """Returns predictable classifier output for PacketService."""

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        rows = []
        for idx in range(len(df)):
            non_null = int(df.iloc[idx].notna().sum())
            sparse = non_null <= 2
            if sparse:
                rows.append(
                    {
                        "prediction": "Normal",
                        "confidence": 0.0,
                        "raw_model_prediction": "Insufficient Evidence",
                        "raw_model_confidence": 0.0,
                        "prob_Normal": 1.0,
                        "prob_Suspicious": 0.0,
                        "prob_Malicious": 0.0,
                        "feature_coverage": 0.15,
                        "missing_feature_count": 30,
                        "traffic_schema": "insufficient-live-flow-features",
                    }
                )
            else:
                rows.append(
                    {
                        "prediction": "Normal",
                        "confidence": 0.92,
                        "raw_model_prediction": "Benign",
                        "raw_model_confidence": 0.88,
                        "prob_Normal": 0.92,
                        "prob_Suspicious": 0.06,
                        "prob_Malicious": 0.02,
                        "feature_coverage": 0.88,
                        "missing_feature_count": 2,
                        "traffic_schema": "cicids-flow",
                    }
                )
        return pd.DataFrame(rows)


class FakeFirewallPipeline:
    """Returns predictable firewall pipeline output for FirewallService."""

    def predict(self, df: pd.DataFrame) -> dict:
        return {
            "validation_report": {
                "input_rows": len(df),
                "valid_rows": len(df),
                "dropped_rows": 0,
                "duplicates_removed": 0,
                "warnings": [],
            },
            "threat_signals": [],
            "anomaly_df": pd.DataFrame(),
            "cluster_df": pd.DataFrame(),
        }

    def ingest_realtime(self, event: dict) -> dict:
        return {
            "buffered_events": 1,
            "scored_events": 1,
            "threat_signals": [],
        }


def build_test_registry() -> ModelRegistry:
    """Build a ModelRegistry that always reports models as available."""
    classifier = FakePacketClassifier()
    pipeline = FakeFirewallPipeline()
    return ModelRegistry(
        packet_classifier=classifier,
        packet_classifier_available=True,
        packet_classifier_meta={
            "engine": "cs-fyp_xgboost",
            "model_type": DEFAULT_PACKET_MODEL_TYPE,
        },
        firewall_pipelines={DEFAULT_CLUSTERING_ALGORITHM: pipeline},
        firewall_pipeline=pipeline,
        firewall_pipeline_available=True,
        firewall_pipeline_meta={
            "available_clustering_algorithms": [DEFAULT_CLUSTERING_ALGORITHM],
            "default_clustering_algorithm": DEFAULT_CLUSTERING_ALGORITHM,
        },
    )
