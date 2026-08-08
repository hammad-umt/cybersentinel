"""Canonical 23-feature vector for CICIDS-style flow data."""

from typing import List

FEATURE_NAMES: List[str] = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_length_fwd",
    "total_length_bwd",
    "fwd_packet_length_max",
    "bwd_packet_length_max",
    "flow_bytes_per_s",
    "flow_packets_per_s",
    "flow_iat_mean",
    "flow_iat_std",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "syn_flag_count",
    "ack_flag_count",
    "fin_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "urg_flag_count",
    "down_up_ratio",
    "avg_packet_size",
    "unique_dest_ports",
    "failed_connections",
]

ATTACK_CLASSES: List[str] = [
    "Benign",
    "DDoS",
    "DoS",
    "PortScan",
    "Bot",
    "Brute Force",
    "Web Attack",
]

# cs-fyp 7-class → Flutter 3-class
ATTACK_TO_FLUTTER = {
    "Benign": "Normal",
    "DDoS": "Malicious",
    "DoS": "Malicious",
    "PortScan": "Suspicious",
    "Bot": "Suspicious",
    "Brute Force": "Malicious",
    "Web Attack": "Suspicious",
}

FLUTTER_CLASSES = ("Normal", "Suspicious", "Malicious")
INSUFFICIENT_EVIDENCE_LABEL = "Insufficient Evidence"

# Public granular attack labels exposed in API (Benign + 6 attack types)
PUBLIC_ATTACK_TYPES = (
    "Benign",
    "DDoS",
    "DoS",
    "PortScan",
    "Botnet",
    "Brute Force",
    "Web Attack",
    "Insufficient Evidence",
    "Unknown",
)

# Internal model class → public API label
MODEL_TO_PUBLIC_ATTACK: dict[str, str] = {
    "Benign": "Benign",
    "DDoS": "DDoS",
    "DoS": "DoS",
    "PortScan": "PortScan",
    "Bot": "Botnet",
    "Brute Force": "Brute Force",
    "Web Attack": "Web Attack",
}
MIN_PRODUCTION_FEATURE_COVERAGE = 0.65
DEGRADED_FEATURE_COVERAGE = 0.90

# Canonical API + optional CSV import aliases (not accepted on JSON classify body)
COLUMN_ALIASES: dict[str, list[str]] = {
    "flow_duration": ["Flow Duration"],
    "total_fwd_packets": ["Total Fwd Packets"],
    "total_bwd_packets": ["Total Backward Packets"],
    "total_length_fwd": ["Total Length of Fwd Packets"],
    "total_length_bwd": ["Total Length of Bwd Packets"],
    "fwd_packet_length_max": ["Fwd Packet Length Max"],
    "bwd_packet_length_max": ["Bwd Packet Length Max"],
    "flow_bytes_per_s": ["Flow Bytes/s"],
    "flow_packets_per_s": ["Flow Packets/s"],
    "flow_iat_mean": ["Flow IAT Mean"],
    "flow_iat_std": ["Flow IAT Std"],
    "fwd_iat_mean": ["Fwd IAT Mean"],
    "bwd_iat_mean": ["Bwd IAT Mean"],
    "syn_flag_count": ["SYN Flag Count"],
    "ack_flag_count": ["ACK Flag Count"],
    "fin_flag_count": ["FIN Flag Count"],
    "rst_flag_count": ["RST Flag Count"],
    "psh_flag_count": ["PSH Flag Count"],
    "urg_flag_count": ["URG Flag Count"],
    "avg_packet_size": ["Average Packet Size", "Packet Length Mean"],
}
