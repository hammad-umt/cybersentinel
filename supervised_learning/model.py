"""
CyberSentinel supervised packet classification pipeline.

Dataset: CICIDS2017
Primary model: RandomForestClassifier
Output classes: Normal, Suspicious, Malicious

Examples:
    python model.py --data_path ./dataset --output_dir ./models
    python model.py --data_path ./dataset --sample 200000 --cv_folds 3
    python model.py --data_path ./dataset --rows_per_file 10000
    python model.py --predict_csv ./dataset/Monday-WorkingHours.pcap_ISCX.csv
"""

from __future__ import annotations

import argparse
import glob
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, LabelEncoder, StandardScaler

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger(__name__)

RANDOM_STATE = 42
ARTIFACT_BUNDLE = "packet_classifier_pipeline.joblib"
MIN_PRODUCTION_FEATURE_COVERAGE = 0.65
DEGRADED_FEATURE_COVERAGE = 0.90
INSUFFICIENT_EVIDENCE_LABEL = "Insufficient Evidence"
DEFAULT_TRAINING_ROWS_PER_FILE = 10_000


LABEL_MAP = {
    "BENIGN": "Normal",
    "Benign": "Normal",
    "benign": "Normal",
    "Bot": "Suspicious",
    "Infiltration": "Suspicious",
    "PortScan": "Suspicious",
    "FTP-Patator": "Suspicious",
    "SSH-Patator": "Suspicious",
    "Heartbleed": "Suspicious",
    "DoS slowloris": "Malicious",
    "DoS Slowhttptest": "Malicious",
    "DoS Hulk": "Malicious",
    "DoS GoldenEye": "Malicious",
    "DDoS": "Malicious",
    "Web Attack Brute Force": "Malicious",
    "Web Attack - Brute Force": "Malicious",
    "Web Attack XSS": "Malicious",
    "Web Attack - XSS": "Malicious",
    "Web Attack Sql Injection": "Malicious",
    "Web Attack - Sql Injection": "Malicious",
    "Web Attack \x96 Brute Force": "Malicious",
    "Web Attack \x96 XSS": "Malicious",
    "Web Attack \x96 Sql Injection": "Malicious",
    "Web Attack \u2013 Brute Force": "Malicious",
    "Web Attack \u2013 XSS": "Malicious",
    "Web Attack \u2013 Sql Injection": "Malicious",
    "Web Attack \ufffd Brute Force": "Malicious",
    "Web Attack \ufffd XSS": "Malicious",
    "Web Attack \ufffd Sql Injection": "Malicious",
}


# Keep this list aligned with flow features that a live collector can produce.
SELECTED_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Active Mean",
    "Idle Mean",
]


DROP_IF_PRESENT = {
    "Flow ID",
    "Source IP",
    "Src IP",
    "Destination IP",
    "Dst IP",
    "Source Port",
    "Src Port",
    "Destination Port",
    "Dst Port",
    "Timestamp",
}


LIVE_FEATURE_ALIASES = {
    "Flow Duration": [
        "duration_us",
        "flow_duration_us",
        "Flow Duration",
        "flow.duration",
    ],
    "Total Fwd Packets": [
        "orig_pkts",
        "src_pkts",
        "fwd_pkts",
        "packets_toserver",
        "flow.pkts_toserver",
        "Total Fwd Packets",
    ],
    "Total Backward Packets": [
        "resp_pkts",
        "dst_pkts",
        "bwd_pkts",
        "packets_toclient",
        "flow.pkts_toclient",
        "Total Backward Packets",
    ],
    "Total Length of Fwd Packets": [
        "orig_ip_bytes",
        "src_bytes",
        "fwd_bytes",
        "bytes_toserver",
        "flow.bytes_toserver",
        "Total Length of Fwd Packets",
    ],
    "Total Length of Bwd Packets": [
        "resp_ip_bytes",
        "dst_bytes",
        "bwd_bytes",
        "bytes_toclient",
        "flow.bytes_toclient",
        "Total Length of Bwd Packets",
    ],
    "Flow IAT Mean": ["flow_iat_mean", "flow.iat_mean", "Flow IAT Mean"],
    "Flow IAT Std": ["flow_iat_std", "flow.iat_std", "Flow IAT Std"],
    "Fwd IAT Mean": ["fwd_iat_mean", "orig_iat_mean", "Fwd IAT Mean"],
    "Bwd IAT Mean": ["bwd_iat_mean", "resp_iat_mean", "Bwd IAT Mean"],
    "Fwd PSH Flags": ["fwd_psh_flags", "tcp.psh_toserver", "Fwd PSH Flags"],
    "Fwd URG Flags": ["fwd_urg_flags", "tcp.urg_toserver", "Fwd URG Flags"],
    "Packet Length Std": ["packet_length_std", "pkt_len_std", "Packet Length Std"],
    "FIN Flag Count": ["fin_count", "tcp.fin", "FIN Flag Count"],
    "SYN Flag Count": ["syn_count", "tcp.syn", "SYN Flag Count"],
    "RST Flag Count": ["rst_count", "tcp.rst", "RST Flag Count"],
    "PSH Flag Count": ["psh_count", "tcp.psh", "PSH Flag Count"],
    "ACK Flag Count": ["ack_count", "tcp.ack", "ACK Flag Count"],
    "URG Flag Count": ["urg_count", "tcp.urg", "URG Flag Count"],
    "Init_Win_bytes_forward": ["init_win_bytes_forward", "tcp.window_size_toserver", "Init_Win_bytes_forward"],
    "Init_Win_bytes_backward": [
        "init_win_bytes_backward",
        "tcp.window_size_toclient",
        "Init_Win_bytes_backward",
    ],
    "Active Mean": ["active_mean", "flow.active_mean", "Active Mean"],
    "Idle Mean": ["idle_mean", "flow.idle_mean", "Idle Mean"],
}

SECONDS_DURATION_ALIASES = {"duration", "flow_duration", "event.duration"}
MILLISECONDS_DURATION_ALIASES = {"duration_ms", "flow_duration_ms"}
MICROSECONDS_PER_SECOND = 1_000_000.0


@dataclass
class TrainingReport:
    accuracy: float
    precision_weighted: float
    recall_weighted: float
    f1_weighted: float
    roc_auc_ovr_weighted: float | None
    classification_report: dict[str, Any]
    confusion_matrix: list[list[int]]
    classes: list[str]
    class_distribution: dict[str, int]
    feature_importances: dict[str, float]
    cv_f1_weighted_mean: float | None = None
    cv_f1_weighted_std: float | None = None


@dataclass
class CyberSentinelPacketClassifier:
    """Production-inspired training and inference wrapper for CICIDS2017 flows."""

    features: list[str] = field(default_factory=lambda: list(SELECTED_FEATURES))
    random_state: int = RANDOM_STATE
    pipeline: Pipeline | None = None
    label_encoder: LabelEncoder | None = None
    training_report: TrainingReport | None = None

    def train(
        self,
        df: pd.DataFrame,
        test_size: float = 0.2,
        cv_folds: int = 0,
    ) -> TrainingReport:
        """Clean labels, split data, fit preprocessing on train only, and evaluate."""
        prepared = prepare_training_frame(df)
        prepared = prepared.drop_duplicates()
        log.info("Rows after label cleaning and duplicate removal: %s", f"{len(prepared):,}")

        X = self._select_training_features(prepared)
        y = prepared["class"]
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)

        X_train, X_test, y_train, y_test = safe_train_test_split(
            X,
            y_encoded,
            test_size=test_size,
            random_state=self.random_state,
            class_names=list(self.label_encoder.classes_),
        )

        self.pipeline = self._build_pipeline()
        self.pipeline.fit(X_train, y_train)
        self.training_report = self.evaluate(X_test, y_test, y)

        if cv_folds and cv_folds > 1:
            self._add_cross_validation(X_train, y_train, cv_folds)

        return self.training_report

    def predict(self, flows: pd.DataFrame) -> pd.DataFrame:
        """Classify new flow records without retraining."""
        self._ensure_loaded()
        X, compatibility = self._prepare_inference_features(flows)
        encoded = self.pipeline.predict(X)
        labels = self.label_encoder.inverse_transform(encoded)

        result = pd.DataFrame({"prediction": labels}, index=flows.index)
        if hasattr(self.pipeline, "predict_proba"):
            probabilities = self.pipeline.predict_proba(X)
            for class_name, idx in zip(self.label_encoder.classes_, range(len(self.label_encoder.classes_))):
                result[f"prob_{class_name}"] = probabilities[:, idx]
            result["confidence"] = probabilities.max(axis=1)
        else:
            result["confidence"] = np.nan

        insufficient_evidence = compatibility["feature_coverage"] < MIN_PRODUCTION_FEATURE_COVERAGE
        degraded_evidence = (
            compatibility["feature_coverage"] >= MIN_PRODUCTION_FEATURE_COVERAGE
        ) & (compatibility["feature_coverage"] < DEGRADED_FEATURE_COVERAGE)
        result.loc[insufficient_evidence, "prediction"] = INSUFFICIENT_EVIDENCE_LABEL
        result.loc[insufficient_evidence, "confidence"] = 0.0
        result.loc[degraded_evidence, "confidence"] = (
            result.loc[degraded_evidence, "confidence"] * compatibility.loc[degraded_evidence, "feature_coverage"]
        )
        result["feature_coverage"] = compatibility["feature_coverage"]
        result["missing_feature_count"] = compatibility["missing_feature_count"]
        result["missing_features"] = compatibility["missing_features"]
        result["traffic_schema"] = compatibility["traffic_schema"]
        return result

    def save_model(self, output_dir: str | Path) -> dict[str, str]:
        """Persist the full inference bundle and legacy-compatible artifacts."""
        self._ensure_loaded()
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        bundle = {
            "pipeline": self.pipeline,
            "label_encoder": self.label_encoder,
            "features": self.features,
            "training_report": self.training_report.__dict__ if self.training_report else None,
            "label_map": LABEL_MAP,
            "live_feature_aliases": LIVE_FEATURE_ALIASES,
            "required_features": self.features,
        }
        bundle_path = output_path / ARTIFACT_BUNDLE
        joblib.dump(bundle, bundle_path)

        model = self.pipeline.named_steps["model"]
        scaler = self.pipeline.named_steps["scaler"]
        joblib.dump(model, output_path / "packet_classifier.pkl")
        joblib.dump(scaler, output_path / "packet_scaler.pkl")
        joblib.dump(self.label_encoder, output_path / "packet_label_encoder.pkl")
        joblib.dump(self.features, output_path / "packet_features.pkl")

        metrics_path = output_path / "packet_classifier_metrics.json"
        if self.training_report:
            with metrics_path.open("w", encoding="utf-8") as f:
                json.dump(self.training_report.__dict__, f, indent=2)

        log.info("Saved CyberSentinel classifier bundle to %s", bundle_path)
        return {
            "bundle_path": str(bundle_path),
            "model_path": str(output_path / "packet_classifier.pkl"),
            "scaler_path": str(output_path / "packet_scaler.pkl"),
            "label_encoder_path": str(output_path / "packet_label_encoder.pkl"),
            "features_path": str(output_path / "packet_features.pkl"),
            "metrics_path": str(metrics_path),
        }

    @classmethod
    def load_model(cls, model_dir: str | Path) -> "CyberSentinelPacketClassifier":
        """Load the preferred bundled artifact, with fallback to legacy files."""
        model_path = Path(model_dir)
        bundle_path = model_path / ARTIFACT_BUNDLE

        instance = cls()
        if bundle_path.exists():
            bundle = joblib.load(bundle_path)
            instance.pipeline = bundle["pipeline"]
            instance.label_encoder = bundle["label_encoder"]
            instance.features = list(bundle["features"])
            report = bundle.get("training_report")
            instance.training_report = TrainingReport(**report) if report else None
            return instance

        model = joblib.load(model_path / "packet_classifier.pkl")
        scaler = joblib.load(model_path / "packet_scaler.pkl")
        instance.label_encoder = joblib.load(model_path / "packet_label_encoder.pkl")
        instance.features = joblib.load(model_path / "packet_features.pkl")
        instance.pipeline = Pipeline(
            steps=[
                ("legacy_fill", FunctionTransformer(fill_missing_with_zero, validate=False)),
                ("scaler", scaler),
                ("model", model),
            ]
        )
        log.warning(
            "Loaded legacy artifacts. Retrain once to save the unified %s bundle.",
            ARTIFACT_BUNDLE,
        )
        return instance

    def evaluate(self, X_test: pd.DataFrame, y_test: np.ndarray, original_y: pd.Series) -> TrainingReport:
        """Generate SOC-relevant metrics, including per-class precision and recall."""
        self._ensure_loaded()
        y_pred = self.pipeline.predict(X_test)

        roc_auc = None
        if hasattr(self.pipeline, "predict_proba") and len(self.label_encoder.classes_) > 1:
            try:
                probabilities = self.pipeline.predict_proba(X_test)
                roc_auc = float(
                    roc_auc_score(
                        y_test,
                        probabilities,
                        multi_class="ovr",
                        average="weighted",
                    )
                )
            except ValueError as exc:
                log.warning("ROC-AUC could not be computed: %s", exc)

        feature_importances = self._feature_importances()
        labels = np.arange(len(self.label_encoder.classes_))
        report = TrainingReport(
            accuracy=float(accuracy_score(y_test, y_pred)),
            precision_weighted=float(precision_score(y_test, y_pred, average="weighted", zero_division=0)),
            recall_weighted=float(recall_score(y_test, y_pred, average="weighted", zero_division=0)),
            f1_weighted=float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
            roc_auc_ovr_weighted=roc_auc,
            classification_report=classification_report(
                y_test,
                y_pred,
                labels=labels,
                target_names=list(self.label_encoder.classes_),
                output_dict=True,
                zero_division=0,
            ),
            confusion_matrix=confusion_matrix(y_test, y_pred, labels=labels).tolist(),
            classes=list(self.label_encoder.classes_),
            class_distribution={str(k): int(v) for k, v in original_y.value_counts().to_dict().items()},
            feature_importances=feature_importances,
        )
        log_training_report(report)
        return report

    def _build_pipeline(self) -> Pipeline:
        model = RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_split=4,
            min_samples_leaf=2,
            max_features="sqrt",
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=self.random_state,
        )
        return Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
                ("model", model),
            ]
        )

    def _select_training_features(self, df: pd.DataFrame) -> pd.DataFrame:
        available = [feature for feature in self.features if feature in df.columns]
        missing = sorted(set(self.features) - set(available))
        if missing:
            log.warning("Missing selected features excluded from training: %s", missing)
        if not available:
            raise ValueError("None of the selected CICIDS2017 features are available.")
        self.features = available
        return coerce_numeric_features(df, self.features)

    def _prepare_inference_features(self, flows: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
        normalized = normalize_columns(flows.copy())
        normalized = standardize_live_flow_features(normalized)
        for feature in self.features:
            if feature not in normalized.columns:
                normalized[feature] = np.nan
        X = coerce_numeric_features(normalized, self.features)
        compatibility = assess_feature_coverage(X)
        low_coverage = compatibility["feature_coverage"] < MIN_PRODUCTION_FEATURE_COVERAGE
        if low_coverage.any():
            log.warning(
                "Live traffic compatibility warning: %s row(s) have <65%% feature coverage. "
                "Returning Insufficient Evidence instead of a Normal/Suspicious/Malicious verdict. "
                "Prefer CICFlowMeter-compatible flow extraction for production-quality predictions.",
                int(low_coverage.sum()),
            )
        return X, compatibility

    def _feature_importances(self) -> dict[str, float]:
        model = self.pipeline.named_steps["model"]
        importances = getattr(model, "feature_importances_", None)
        if importances is None:
            return {}
        ranked = pd.Series(importances, index=self.features).sort_values(ascending=False)
        return {str(feature): float(value) for feature, value in ranked.items()}

    def _add_cross_validation(self, X_train: pd.DataFrame, y_train: np.ndarray, cv_folds: int) -> None:
        min_class_count = int(pd.Series(y_train).value_counts().min())
        folds = min(cv_folds, min_class_count)
        if folds < 2:
            log.warning("Skipping cross-validation because at least one class has fewer than 2 samples.")
            return
        cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=self.random_state)
        scores = cross_val_score(
            self._build_pipeline(),
            X_train,
            y_train,
            cv=cv,
            scoring="f1_weighted",
            n_jobs=-1,
        )
        self.training_report.cv_f1_weighted_mean = float(scores.mean())
        self.training_report.cv_f1_weighted_std = float(scores.std())
        log.info("CV weighted F1: %.4f +/- %.4f", scores.mean(), scores.std())

    def _ensure_loaded(self) -> None:
        if self.pipeline is None or self.label_encoder is None:
            raise RuntimeError("Model is not trained or loaded.")


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize CICIDS2017's inconsistent whitespace and dash characters."""
    df.columns = (
        df.columns.astype(str)
        .str.strip()
        .str.replace("\u2013", "-", regex=False)
        .str.replace("\x96", "-", regex=False)
    )
    return df


def normalize_lookup_key(value: str) -> str:
    return (
        str(value)
        .strip()
        .lower()
        .replace(" ", "")
        .replace("_", "")
        .replace("-", "")
        .replace(".", "")
        .replace("/", "")
    )


def first_available_numeric(df: pd.DataFrame, aliases: list[str] | set[str]) -> pd.Series | None:
    lookup = {normalize_lookup_key(column): column for column in df.columns}
    for alias in aliases:
        column = lookup.get(normalize_lookup_key(alias))
        if column is not None:
            return pd.to_numeric(df[column], errors="coerce")
    return None


def standardize_live_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    """Translate common live flow-exporter fields into CICIDS-style features.

    Best compatibility comes from CICFlowMeter-compatible exporters because they
    provide packet length, IAT, active, and idle statistics directly. This
    adapter improves real deployment ergonomics for Zeek, Suricata, Tshark, and
    firewall-flow rows by deriving the safe aggregate features those logs expose.
    """
    standardized = df.copy()

    for feature, aliases in LIVE_FEATURE_ALIASES.items():
        if feature not in standardized.columns:
            series = first_available_numeric(standardized, aliases)
            if series is not None:
                standardized[feature] = series

    if "Flow Duration" not in standardized.columns:
        duration_seconds = first_available_numeric(standardized, SECONDS_DURATION_ALIASES)
        duration_ms = first_available_numeric(standardized, MILLISECONDS_DURATION_ALIASES)
        if duration_seconds is not None:
            standardized["Flow Duration"] = duration_seconds * MICROSECONDS_PER_SECOND
        elif duration_ms is not None:
            standardized["Flow Duration"] = duration_ms * 1_000.0

    duration_seconds = safe_divide(
        pd.to_numeric(standardized.get("Flow Duration"), errors="coerce"),
        MICROSECONDS_PER_SECOND,
    )
    fwd_packets = pd.to_numeric(standardized.get("Total Fwd Packets"), errors="coerce")
    bwd_packets = pd.to_numeric(standardized.get("Total Backward Packets"), errors="coerce")
    fwd_bytes = pd.to_numeric(standardized.get("Total Length of Fwd Packets"), errors="coerce")
    bwd_bytes = pd.to_numeric(standardized.get("Total Length of Bwd Packets"), errors="coerce")
    total_packets = fwd_packets.add(bwd_packets, fill_value=0)
    total_bytes = fwd_bytes.add(bwd_bytes, fill_value=0)

    derived = {
        "Flow Bytes/s": safe_divide(total_bytes, duration_seconds),
        "Flow Packets/s": safe_divide(total_packets, duration_seconds),
        "Fwd Packets/s": safe_divide(fwd_packets, duration_seconds),
        "Bwd Packets/s": safe_divide(bwd_packets, duration_seconds),
        "Fwd Packet Length Mean": safe_divide(fwd_bytes, fwd_packets),
        "Bwd Packet Length Mean": safe_divide(bwd_bytes, bwd_packets),
        "Packet Length Mean": safe_divide(total_bytes, total_packets),
        "Average Packet Size": safe_divide(total_bytes, total_packets),
        "Avg Fwd Segment Size": safe_divide(fwd_bytes, fwd_packets),
        "Avg Bwd Segment Size": safe_divide(bwd_bytes, bwd_packets),
    }

    for feature, values in derived.items():
        if feature not in standardized.columns:
            standardized[feature] = values

    return standardized


def safe_divide(numerator: Any, denominator: Any) -> pd.Series:
    numerator_series = to_series(numerator)
    if np.isscalar(denominator):
        if denominator == 0:
            return numerator_series * np.nan
        return numerator_series / denominator
    denominator_series = to_series(denominator).replace(0, np.nan)
    if np.isscalar(numerator):
        numerator_series = pd.Series(numerator, index=denominator_series.index)
    return numerator_series.divide(denominator_series)


def to_series(value: Any) -> pd.Series:
    if isinstance(value, pd.Series):
        return pd.to_numeric(value, errors="coerce")
    if value is None:
        return pd.Series(dtype="float64")
    return pd.to_numeric(pd.Series(value), errors="coerce")


def assess_feature_coverage(X: pd.DataFrame) -> pd.DataFrame:
    present_counts = X.notna().sum(axis=1)
    coverage = present_counts / max(len(X.columns), 1)
    missing_features = X.apply(lambda row: ",".join(row.index[row.isna()].tolist()), axis=1)
    schema = np.where(
        coverage >= 0.9,
        "cicflowmeter-compatible",
        np.where(coverage >= 0.65, "partially-derived-live-flow", "insufficient-live-flow-features"),
    )
    return pd.DataFrame(
        {
            "feature_coverage": coverage,
            "missing_feature_count": X.isna().sum(axis=1).astype(int),
            "missing_features": missing_features,
            "traffic_schema": schema,
        },
        index=X.index,
    )


def normalize_label(value: Any) -> str:
    return str(value).strip().replace("\u2013", "-").replace("\x96", "-").replace("\ufffd", "-")


def find_label_column(df: pd.DataFrame) -> str:
    for column in df.columns:
        if column.strip().lower() == "label":
            return column
    raise ValueError("Cannot find a CICIDS2017 Label column.")


def prepare_training_frame(df: pd.DataFrame) -> pd.DataFrame:
    df = normalize_columns(df.copy())
    label_col = find_label_column(df)
    df["class"] = df[label_col].map(lambda value: LABEL_MAP.get(normalize_label(value)))

    unknown = df["class"].isna().sum()
    if unknown:
        unknown_values = sorted(df.loc[df["class"].isna(), label_col].astype(str).unique())
        log.warning("Dropping %s rows with unmapped labels: %s", f"{unknown:,}", unknown_values)
        df = df.dropna(subset=["class"])

    leak_columns = sorted(DROP_IF_PRESENT.intersection(df.columns))
    if leak_columns:
        log.info("Ignoring identifier/time columns that can cause dataset memorization: %s", leak_columns)

    return df


def coerce_numeric_features(df: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    X = df.loc[:, features].copy()
    for column in X.columns:
        X[column] = pd.to_numeric(X[column], errors="coerce")
    return X.replace([np.inf, -np.inf], np.nan)


def safe_train_test_split(
    X: pd.DataFrame,
    y: np.ndarray,
    test_size: float,
    random_state: int,
    class_names: list[str],
) -> tuple[pd.DataFrame, pd.DataFrame, np.ndarray, np.ndarray]:
    """
    Split while handling tiny temporary training slices.

    The first 10k rows per CICIDS file can leave a class with only one unique
    row after duplicate removal. Stratified splitting cannot place a singleton
    class in both train and test, so singleton classes stay in training and the
    remaining rows are split normally.
    """
    counts = pd.Series(y).value_counts()
    rare_classes = set(counts[counts < 2].index.tolist())
    if not rare_classes:
        return train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=random_state,
            stratify=y,
        )

    rare_names = [class_names[int(idx)] for idx in sorted(rare_classes)]
    log.warning(
        "Keeping rare class(es) only in training because they have fewer than 2 rows: %s",
        rare_names,
    )

    rare_mask = pd.Series(y, index=X.index).isin(rare_classes)
    X_rare = X.loc[rare_mask]
    y_rare = y[rare_mask.to_numpy()]
    X_common = X.loc[~rare_mask]
    y_common = y[(~rare_mask).to_numpy()]

    common_counts = pd.Series(y_common).value_counts()
    stratify = y_common if len(common_counts) > 1 and int(common_counts.min()) >= 2 else None
    if stratify is None:
        log.warning("Using an unstratified split for common classes because class counts are still too small.")

    X_train, X_test, y_train, y_test = train_test_split(
        X_common,
        y_common,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )
    X_train = pd.concat([X_train, X_rare], axis=0)
    y_train = np.concatenate([y_train, y_rare])
    return X_train, X_test, y_train, y_test


def fill_missing_with_zero(X: pd.DataFrame | np.ndarray) -> pd.DataFrame | np.ndarray:
    """Reproduce the original legacy inference behavior for old artifacts."""
    if isinstance(X, pd.DataFrame):
        return X.fillna(0)
    return np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)


def load_cicids2017(
    data_path: str | Path,
    sample: int | None = None,
    rows_per_file: int | None = DEFAULT_TRAINING_ROWS_PER_FILE,
) -> pd.DataFrame:
    """Load CICIDS2017 CSV files from a file or directory."""
    path = Path(data_path)
    if path.is_file():
        csv_files = [path]
    else:
        csv_files = [Path(file) for file in glob.glob(str(path / "*.csv"))]
        if not csv_files:
            csv_files = [Path(file) for file in glob.glob(str(path / "**" / "*.csv"), recursive=True)]

    if not csv_files:
        raise FileNotFoundError(f"No CSV files found under {path}")

    frames = []
    for csv_file in sorted(csv_files):
        log.info("Loading %s", csv_file.name)
        frame = pd.read_csv(csv_file, low_memory=False, nrows=rows_per_file)
        if rows_per_file:
            log.info("Using first %s row(s) from %s", f"{len(frame):,}", csv_file.name)
        frames.append(normalize_columns(frame))

    df = pd.concat(frames, ignore_index=True)
    log.info("Loaded %s rows from %s CSV file(s)", f"{len(df):,}", len(csv_files))
    if sample and sample < len(df):
        df = df.sample(n=sample, random_state=RANDOM_STATE).reset_index(drop=True)
        log.info("Sampled down to %s rows", f"{sample:,}")
    return df


def log_training_report(report: TrainingReport) -> None:
    log.info("Test accuracy: %.4f", report.accuracy)
    log.info("Weighted precision: %.4f", report.precision_weighted)
    log.info("Weighted recall: %.4f", report.recall_weighted)
    log.info("Weighted F1: %.4f", report.f1_weighted)
    if report.roc_auc_ovr_weighted is not None:
        log.info("Weighted ROC-AUC OVR: %.4f", report.roc_auc_ovr_weighted)
    log.info("Classes: %s", report.classes)
    log.info("Class distribution: %s", report.class_distribution)
    log.info("Confusion matrix: %s", report.confusion_matrix)
    top_features = dict(list(report.feature_importances.items())[:10])
    log.info("Top feature importances: %s", top_features)


def train(
    X: pd.DataFrame,
    y: pd.Series,
    features: list[str],
) -> dict[str, Any]:
    """Backward-compatible helper for older imports."""
    df = X.copy()
    df["class"] = y
    classifier = CyberSentinelPacketClassifier(features=features)
    report = classifier.train(df)
    return {
        "model": classifier.pipeline.named_steps["model"],
        "scaler": classifier.pipeline.named_steps["scaler"],
        "label_encoder": classifier.label_encoder,
        "features": classifier.features,
        "metrics": report.__dict__,
        "classifier": classifier,
    }


def preprocess(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    """Backward-compatible preprocessing helper."""
    prepared = prepare_training_frame(df)
    features = [feature for feature in SELECTED_FEATURES if feature in prepared.columns]
    return coerce_numeric_features(prepared, features), prepared["class"].copy(), features


def save_artifacts(artifacts: dict[str, Any], output_dir: str) -> dict[str, str]:
    """Backward-compatible artifact saver."""
    classifier = artifacts.get("classifier")
    if classifier is None:
        classifier = CyberSentinelPacketClassifier(features=artifacts["features"])
        classifier.pipeline = Pipeline(
            steps=[
                ("legacy_fill", FunctionTransformer(fill_missing_with_zero, validate=False)),
                ("scaler", artifacts["scaler"]),
                ("model", artifacts["model"]),
            ]
        )
        classifier.label_encoder = artifacts["label_encoder"]
    return classifier.save_model(output_dir)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CyberSentinel supervised packet classifier")
    parser.add_argument("--data_path", default="./dataset", help="CSV file or folder containing CICIDS2017 CSV files")
    parser.add_argument("--sample", type=int, default=None, help="Optional random sample size for faster training")
    parser.add_argument(
        "--rows_per_file",
        type=int,
        default=DEFAULT_TRAINING_ROWS_PER_FILE,
        help="Read only the first N rows from each CSV file during training. Use 0 to train on full CSV files.",
    )
    parser.add_argument("--output_dir", default="./models", help="Directory for trained artifacts")
    parser.add_argument("--test_size", type=float, default=0.2, help="Holdout fraction for evaluation")
    parser.add_argument("--cv_folds", type=int, default=0, help="Optional stratified CV folds on the training set")
    parser.add_argument("--predict_csv", default=None, help="Classify a CSV file with a saved model instead of training")
    parser.add_argument("--limit", type=int, default=10, help="Rows to predict when using --predict_csv")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.predict_csv:
        classifier = CyberSentinelPacketClassifier.load_model(args.output_dir)
        flows = pd.read_csv(args.predict_csv, low_memory=False).head(args.limit)
        predictions = classifier.predict(flows)
        print(predictions.to_string(index=False))
        return

    log.info("CyberSentinel supervised packet classifier training")
    rows_per_file = args.rows_per_file if args.rows_per_file > 0 else None
    df = load_cicids2017(args.data_path, sample=args.sample, rows_per_file=rows_per_file)
    classifier = CyberSentinelPacketClassifier()
    classifier.train(df, test_size=args.test_size, cv_folds=args.cv_folds)
    classifier.save_model(args.output_dir)


if __name__ == "__main__":
    main()
