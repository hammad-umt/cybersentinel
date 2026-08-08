"""CICIDS2017 preprocessing for CyberSentinel training."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Tuple

import numpy as np
import pandas as pd

from supervised_learning.train._features import ATTACK_CLASSES, FEATURE_NAMES

logger = logging.getLogger(__name__)

CICIDS_COLUMN_MAP: Dict[str, str] = {
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_bwd_packets",
    "Total Length of Fwd Packets": "total_length_fwd",
    "Total Length of Bwd Packets": "total_length_bwd",
    "Fwd Packet Length Max": "fwd_packet_length_max",
    "Bwd Packet Length Max": "bwd_packet_length_max",
    "Flow Bytes/s": "flow_bytes_per_s",
    "Flow Packets/s": "flow_packets_per_s",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Bwd IAT Mean": "bwd_iat_mean",
    "SYN Flag Count": "syn_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "FIN Flag Count": "fin_flag_count",
    "RST Flag Count": "rst_flag_count",
    "PSH Flag Count": "psh_flag_count",
    "URG Flag Count": "urg_flag_count",
    "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "avg_packet_size",
}

LABEL_MAP: Dict[str, str] = {
    "BENIGN": "Benign",
    "Benign": "Benign",
    "DDoS": "DDoS",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "Heartbleed": "DoS",
    "PortScan": "PortScan",
    "Bot": "Bot",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "Web Attack – Brute Force": "Web Attack",
    "Web Attack - Brute Force": "Web Attack",
    "Web Attack – XSS": "Web Attack",
    "Web Attack - XSS": "Web Attack",
    "Web Attack – Sql Injection": "Web Attack",
    "Web Attack - Sql Injection": "Web Attack",
    "Infiltration": "Bot",
}


def normalize_label(raw_label: str) -> str:
    cleaned = str(raw_label).strip()
    if cleaned in LABEL_MAP:
        return LABEL_MAP[cleaned]
    lower = cleaned.lower()
    for key, value in LABEL_MAP.items():
        if key.lower() in lower:
            return value
    if "web attack" in lower or "xss" in lower or "sql injection" in lower:
        return "Web Attack"
    if "patator" in lower or "brute force" in lower:
        return "Brute Force"
    if "infiltration" in lower:
        return "Bot"
    return "Benign"


def _find_label_column(df: pd.DataFrame) -> str:
    for col in df.columns:
        if col.strip().lower() in ("label", " labels", "labels"):
            return col
    raise ValueError("No Label column found in dataset")


def load_cicids_csv(path: Path) -> pd.DataFrame:
    logger.info("Loading dataset: %s", path)
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    return df


def load_cicids_directory(data_dir: Path) -> pd.DataFrame:
    csv_files = sorted(data_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    frames = [load_cicids_csv(f) for f in csv_files]
    combined = pd.concat(frames, ignore_index=True)
    logger.info("Loaded %d rows from %d files", len(combined), len(csv_files))
    return combined


def extract_features(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    label_col = _find_label_column(df)
    labels = df[label_col].apply(normalize_label).values
    label_to_idx = {name: idx for idx, name in enumerate(ATTACK_CLASSES)}
    y = np.array([label_to_idx.get(lbl, 0) for lbl in labels], dtype=int)

    feature_matrix = np.zeros((len(df), len(FEATURE_NAMES)), dtype=np.float64)

    for cicids_col, feature_name in CICIDS_COLUMN_MAP.items():
        if cicids_col in df.columns:
            idx = FEATURE_NAMES.index(feature_name)
            feature_matrix[:, idx] = pd.to_numeric(df[cicids_col], errors="coerce").fillna(0).values

    if "Destination Port" in df.columns:
        feature_matrix[:, FEATURE_NAMES.index("unique_dest_ports")] = 1.0
    if "RST Flag Count" in df.columns:
        rst = pd.to_numeric(df["RST Flag Count"], errors="coerce").fillna(0).values
        feature_matrix[:, FEATURE_NAMES.index("failed_connections")] = np.where(rst > 5, rst * 0.5, 0)

    feature_matrix = np.nan_to_num(feature_matrix, nan=0.0, posinf=1e9, neginf=-1e9)
    return feature_matrix, y


def rebalance_dataset(
    X: np.ndarray,
    y: np.ndarray,
    benign_max_ratio: float = 3.0,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(random_state)
    benign_idx = np.where(y == 0)[0]
    attack_idx = np.where(y != 0)[0]

    if len(attack_idx) == 0:
        logger.warning("No attack samples found — returning unmodified dataset")
        return X, y

    max_benign = int(len(attack_idx) * benign_max_ratio)
    if len(benign_idx) > max_benign:
        selected_benign = rng.choice(benign_idx, size=max_benign, replace=False)
        logger.info("Undersampled Benign: %d → %d", len(benign_idx), max_benign)
    else:
        selected_benign = benign_idx

    balanced_idx = np.concatenate([selected_benign, attack_idx])
    rng.shuffle(balanced_idx)
    return X[balanced_idx], y[balanced_idx]


def compute_class_weights(y: np.ndarray) -> Dict[int, float]:
    classes, counts = np.unique(y, return_counts=True)
    total = len(y)
    n_classes = len(classes)
    return {int(c): total / (n_classes * cnt) for c, cnt in zip(classes, counts)}


def preprocess_cicids(
    data_path: Path,
    output_dir: Path,
    benign_max_ratio: float = 3.0,
    test_size: float = 0.2,
    random_state: int = 42,
) -> Dict:
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    import joblib

    output_dir.mkdir(parents=True, exist_ok=True)

    df = load_cicids_directory(data_path) if data_path.is_dir() else load_cicids_csv(data_path)

    X, y = extract_features(df)
    original_dist = {ATTACK_CLASSES[i]: int((y == i).sum()) for i in range(len(ATTACK_CLASSES))}
    logger.info("Original class distribution: %s", original_dist)

    X_balanced, y_balanced = rebalance_dataset(X, y, benign_max_ratio=benign_max_ratio)
    balanced_dist = {ATTACK_CLASSES[i]: int((y_balanced == i).sum()) for i in range(len(ATTACK_CLASSES))}
    logger.info("Balanced class distribution: %s", balanced_dist)

    X_train, X_test, y_train, y_test = train_test_split(
        X_balanced, y_balanced, test_size=test_size, random_state=random_state, stratify=y_balanced
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    joblib.dump(scaler, output_dir / "scaler.joblib")
    np.save(output_dir / "X_train.npy", X_train_scaled)
    np.save(output_dir / "X_test.npy", X_test_scaled)
    np.save(output_dir / "y_train.npy", y_train)
    np.save(output_dir / "y_test.npy", y_test)

    metadata = {
        "original_distribution": original_dist,
        "balanced_distribution": balanced_dist,
        "class_weights": compute_class_weights(y_train),
        "train_samples": len(y_train),
        "test_samples": len(y_test),
        "benign_max_ratio": benign_max_ratio,
        "feature_names": FEATURE_NAMES,
    }
    with open(output_dir / "preprocessing_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    logger.info("Preprocessing complete — saved to %s", output_dir)
    return {
        "X_train": X_train_scaled,
        "X_test": X_test_scaled,
        "y_train": y_train,
        "y_test": y_test,
        "scaler": scaler,
        "class_weights": metadata["class_weights"],
        "metadata": metadata,
    }
