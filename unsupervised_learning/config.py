from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass
class PipelineConfig:
    """Configuration for the unsupervised firewall threat detection pipeline."""

    # Model identity and storage
    model_version: str = "cybersentinel-unsupervised-v1"
    model_dir: str = "models"
    anomaly_model_filename: str = "anomaly_model.joblib"
    clustering_model_filename: str = "clustering_model.joblib"

    # Isolation Forest
    if_contamination: float = 0.05
    if_n_estimators: int = 300

    # One-Class SVM is useful for demos but can be costly at enterprise scale.
    enable_ocsvm: bool = False
    ocsvm_nu: float = 0.05
    ocsvm_kernel: str = "rbf"

    # KMeans behavior profiling
    kmeans_n_clusters: int = 3
    kmeans_max_iter: int = 300
    cluster_distance_percentile: float = 95.0
    min_distance_threshold: float = 1.5
    clustering_algorithm: str = "kmeans"
    dbscan_eps: float = 0.8
    dbscan_min_samples: int = 5

    # General
    random_state: int = 42
    timestamp_floor: str = "h"
    default_packet_size: float = 400.0
    default_inter_event_seconds: float = 60.0
    duplicate_subset: Tuple[str, ...] = (
        "timestamp",
        "src_ip",
        "dst_ip",
        "dst_port",
        "protocol",
        "action",
    )

    # Threat scoring thresholds, all on 0-100 scale.
    anomaly_score_medium: float = 35.0
    severity_suspicious: float = 35.0
    severity_malicious: float = 60.0
    severity_critical: float = 80.0

    # Heuristic thresholds for real firewall behavior.
    port_scan_unique_ports: int = 10
    port_scan_score: float = 0.35
    block_ratio: float = 0.45
    off_hours_ratio: float = 0.40
    burst_index: float = 2.0
    destination_diversity: int = 20
    brute_force_block_count: int = 20

    # Schema support. Common vendor fields are normalized into these columns.
    required_columns: List[str] = field(
        default_factory=lambda: [
            "timestamp",
            "src_ip",
            "dst_ip",
            "dst_port",
            "protocol",
            "pkt_size",
            "is_block",
        ]
    )
    column_aliases: Dict[str, List[str]] = field(
        default_factory=lambda: {
            "timestamp": ["time", "event_time", "@timestamp", "date_time", "datetime"],
            "src_ip": ["source_ip", "src", "srcaddr", "srcip", "source.address", "source.ip", "source"],
            "dst_ip": [
                "destination_ip",
                "dst",
                "dstaddr",
                "dstip",
                "dest_ip",
                "destination.address",
                "destination.ip",
                "destination",
            ],
            "dst_port": ["destination_port", "dpt", "dstport", "dst_port", "dest_port", "destination.port"],
            "protocol": ["proto", "ip_protocol", "network.transport"],
            "pkt_size": ["bytes", "bytes_sent", "packet_size", "len", "length", "sentbyte", "sent_bytes"],
            "is_block": ["blocked", "deny", "dropped"],
            "action": ["rule_action", "disposition", "event.action", "status", "act"],
        }
    )
    block_actions: Tuple[str, ...] = (
        "block",
        "blocked",
        "deny",
        "denied",
        "drop",
        "dropped",
        "reject",
        "reset-both",
    )

    # Realtime scoring
    realtime_max_events: int = 5000
    realtime_min_events_per_ip: int = 2

    @property
    def anomaly_model_path(self) -> str:
        return str(Path(self.model_dir) / self.anomaly_model_filename)

    @property
    def clustering_model_path(self) -> str:
        if self.clustering_algorithm == "kmeans":
            return str(Path(self.model_dir) / self.clustering_model_filename)
        return str(Path(self.model_dir) / f"clustering_model.{self.clustering_algorithm}.joblib")
