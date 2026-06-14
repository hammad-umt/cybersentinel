from datetime import datetime, timezone
from typing import Dict, List

import pandas as pd

from config import PipelineConfig


class ThreatSignalEmitter:
    """Fuses anomaly, clustering, and heuristic evidence into source-IP alerts."""

    def __init__(self, config=None):
        self.config = config or PipelineConfig()

    def emit(self, anomaly_df: pd.DataFrame, cluster_df: pd.DataFrame) -> List[Dict[str, object]]:
        now = datetime.now(timezone.utc).isoformat()
        anomaly_ips = self._summarize_anomalies(anomaly_df)
        cluster_ips = self._summarize_clusters(cluster_df)
        signals: List[Dict[str, object]] = []

        for ip in sorted(set(anomaly_ips) | set(cluster_ips)):
            anomaly = anomaly_ips.get(ip, self._empty_anomaly())
            cluster = cluster_ips.get(ip, self._empty_cluster())
            heuristic_score = self._heuristic_score(cluster)
            fused_score = max(
                float(anomaly["anomaly_score"]),
                heuristic_score,
                75.0 if cluster["cluster_label"] == "Attack" else 0.0,
            )

            if fused_score < self.config.severity_suspicious:
                continue

            signals.append(
                {
                    "src_ip": ip,
                    "entity_type": "source_ip",
                    "threat_score": round(fused_score, 2),
                    "anomaly_score": round(float(anomaly["anomaly_score"]), 2),
                    "heuristic_score": round(heuristic_score, 2),
                    "severity": self._severity(fused_score),
                    "cluster_label": cluster["cluster_label"],
                    "attack_signals": int(cluster["attack_signals"]),
                    "consensus_anomaly": bool(anomaly["consensus_anomaly"]),
                    "evidence": self._evidence(anomaly, cluster),
                    "timestamp": now,
                }
            )

        signals.sort(key=lambda item: (item["threat_score"], item["attack_signals"]), reverse=True)
        return signals

    def _summarize_anomalies(self, anomaly_df: pd.DataFrame) -> Dict[str, Dict[str, object]]:
        if anomaly_df is None or anomaly_df.empty:
            return {}
        summaries = {}
        for ip, group in anomaly_df.groupby("src_ip", observed=True):
            max_row = group.loc[group["anomaly_score"].idxmax()]
            summaries[ip] = {
                "anomaly_score": float(max_row["anomaly_score"]),
                "severity": max_row.get("severity", "Normal"),
                "consensus_anomaly": bool(group["consensus_anomaly"].any()),
                "windows_observed": int(len(group)),
            }
        return summaries

    @staticmethod
    def _summarize_clusters(cluster_df: pd.DataFrame) -> Dict[str, Dict[str, object]]:
        if cluster_df is None or cluster_df.empty:
            return {}
        summaries = {}
        for ip, group in cluster_df.groupby("src_ip", observed=True):
            row = group.iloc[0]
            summaries[ip] = {
                "cluster_label": row.get("cluster_interpretation", "Normal"),
                "attack_signals": int(row.get("attack_signal_count", 0)),
                "total_events": int(row.get("total_events", 0)),
                "block_ratio": float(row.get("block_ratio", 0.0)),
                "unique_ports": int(row.get("unique_ports", 0)),
                "dst_ip_diversity": int(row.get("dst_ip_diversity", 0)),
                "distance_outlier": bool(row.get("distance_outlier", False)),
            }
        return summaries

    def _heuristic_score(self, cluster: Dict[str, object]) -> float:
        score = min(100.0, float(cluster["attack_signals"]) * 18.0)
        if cluster["cluster_label"] == "Attack":
            score = max(score, 75.0)
        elif cluster["cluster_label"] == "Suspicious":
            score = max(score, 45.0)
        elif cluster["cluster_label"] == "Isolated":
            score = max(score, 40.0)
        return score

    def _severity(self, score: float) -> str:
        if score >= self.config.severity_critical:
            return "Critical"
        if score >= self.config.severity_malicious:
            return "Malicious-like"
        if score >= self.config.severity_suspicious:
            return "Suspicious"
        return "Normal"

    @staticmethod
    def _evidence(anomaly: Dict[str, object], cluster: Dict[str, object]) -> Dict[str, object]:
        return {
            "windows_observed": anomaly.get("windows_observed", 0),
            "total_events": cluster.get("total_events", 0),
            "block_ratio": cluster.get("block_ratio", 0.0),
            "unique_ports": cluster.get("unique_ports", 0),
            "dst_ip_diversity": cluster.get("dst_ip_diversity", 0),
            "distance_outlier": cluster.get("distance_outlier", False),
        }

    @staticmethod
    def _empty_anomaly() -> Dict[str, object]:
        return {
            "anomaly_score": 0.0,
            "severity": "Normal",
            "consensus_anomaly": False,
            "windows_observed": 0,
        }

    @staticmethod
    def _empty_cluster() -> Dict[str, object]:
        return {
            "cluster_label": "Normal",
            "attack_signals": 0,
            "total_events": 0,
            "block_ratio": 0.0,
            "unique_ports": 0,
            "dst_ip_diversity": 0,
            "distance_outlier": False,
        }
