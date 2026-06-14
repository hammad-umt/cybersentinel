from __future__ import annotations

import random
from typing import Dict, Iterable, List, Tuple

import pandas as pd
from sklearn.metrics import davies_bouldin_score, silhouette_score

from feature_engineering import CLUSTER_FEATURE_COLUMNS


class UnsupervisedEvaluator:
    """Practical validation helpers for unlabeled firewall anomaly detection."""

    @staticmethod
    def inject_port_scan(
        baseline_df: pd.DataFrame,
        attacker_ip: str = "203.0.113.99",
        target_ip: str = "10.0.0.5",
        start_time: str = "2026-06-09 13:00:00",
        ports: Iterable[int] | None = None,
    ) -> Tuple[pd.DataFrame, List[str]]:
        """Append a synthetic vertical port scan and return expected malicious IPs."""
        ports = list(ports or [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080])
        start = pd.Timestamp(start_time)
        attack_rows = [
            {
                "timestamp": start + pd.Timedelta(seconds=i * 2),
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "dst_port": port,
                "protocol": "TCP",
                "pkt_size": 64,
                "is_block": 1,
                "action": "deny",
            }
            for i, port in enumerate(ports)
        ]
        return pd.concat([baseline_df.copy(), pd.DataFrame(attack_rows)], ignore_index=True), [attacker_ip]

    @staticmethod
    def precision_at_k(threat_signals: List[Dict[str, object]], malicious_ips: Iterable[str], k: int = 10) -> float:
        malicious = set(malicious_ips)
        if k <= 0 or not threat_signals:
            return 0.0
        top_k = threat_signals[:k]
        hits = sum(1 for signal in top_k if signal.get("src_ip") in malicious)
        return hits / min(k, len(top_k))

    @staticmethod
    def clustering_metrics(cluster_df: pd.DataFrame) -> Dict[str, float | None]:
        if cluster_df.empty or "kmeans_cluster" not in cluster_df.columns:
            return {"silhouette": None, "davies_bouldin": None}
        labels = cluster_df["kmeans_cluster"]
        if labels.nunique() < 2 or len(cluster_df) <= labels.nunique():
            return {"silhouette": None, "davies_bouldin": None}
        X = cluster_df[CLUSTER_FEATURE_COLUMNS].astype(float)
        return {
            "silhouette": float(silhouette_score(X, labels)),
            "davies_bouldin": float(davies_bouldin_score(X, labels)),
        }

    @staticmethod
    def stability_sample(df: pd.DataFrame, frac: float = 0.8, random_state: int = 42) -> pd.DataFrame:
        """Sample logs for simple score-stability experiments."""
        random.seed(random_state)
        return df.sample(frac=frac, random_state=random_state).reset_index(drop=True)
