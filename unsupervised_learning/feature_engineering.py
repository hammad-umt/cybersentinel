import ipaddress
import logging
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

from config import PipelineConfig

logger = logging.getLogger(__name__)


FEATURE_COLUMNS = [
    "block_frequency",
    "unique_ports_targeted",
    "bytes_per_packet",
    "event_hour",
    "protocol_entropy",
    "dst_ip_diversity",
    "avg_inter_event_time",
    "external_dst_ratio",
]

CLUSTER_FEATURE_COLUMNS = [
    "total_events",
    "block_ratio",
    "unique_ports",
    "avg_bytes_per_packet",
    "protocol_entropy",
    "dst_ip_diversity",
    "avg_inter_event_time",
    "off_hours_ratio",
    "port_scan_score",
    "burst_index",
    "external_dst_ratio",
    "blocked_events",
]


class FirewallLogValidator:
    """Normalizes common firewall schemas into CyberSentinel's canonical columns."""

    def __init__(self, config: PipelineConfig | None = None):
        self.config = config or PipelineConfig()

    def validate(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, object]]:
        if df is None:
            raise ValueError("Input firewall log DataFrame cannot be None")
        if df.empty:
            return pd.DataFrame(columns=self.config.required_columns + ["action"]), {
                "input_rows": 0,
                "valid_rows": 0,
                "dropped_rows": 0,
                "duplicates_removed": 0,
                "warnings": [],
            }

        work = self._apply_aliases(df.copy())
        warnings: List[str] = []

        for col in self.config.required_columns:
            if col not in work.columns:
                if col == "is_block" and "action" in work.columns:
                    work["is_block"] = work["action"].astype(str).str.lower().isin(self.config.block_actions)
                elif col == "pkt_size":
                    work[col] = self.config.default_packet_size
                    warnings.append("Missing packet-size column; default packet size was applied.")
                else:
                    raise ValueError(f"Missing required firewall log column: {col}")

        if "action" not in work.columns:
            work["action"] = np.where(work["is_block"].astype(bool), "block", "allow")

        work["timestamp"] = self._parse_timestamps(work["timestamp"])
        work["src_ip"] = work["src_ip"].astype(str).str.strip()
        work["dst_ip"] = work["dst_ip"].astype(str).str.strip()
        work["protocol"] = work["protocol"].fillna("UNKNOWN").astype(str).str.upper().str.strip()
        work["dst_port"] = pd.to_numeric(work["dst_port"], errors="coerce")
        work["pkt_size"] = pd.to_numeric(work["pkt_size"], errors="coerce").fillna(
            self.config.default_packet_size
        )
        work["is_block"] = self._coerce_block_flag(work)

        valid_ip_mask = work["src_ip"].map(self._is_valid_ip) & work["dst_ip"].map(self._is_valid_ip)
        valid_port_mask = work["dst_port"].between(0, 65535, inclusive="both")
        valid_time_mask = work["timestamp"].notna()
        valid_mask = valid_ip_mask & valid_port_mask & valid_time_mask

        dropped_rows = int((~valid_mask).sum())
        if dropped_rows:
            warnings.append(f"Dropped {dropped_rows} malformed rows with invalid timestamp/IP/port.")

        work = work.loc[valid_mask].copy()
        before_dedup = len(work)
        dedup_cols = [c for c in self.config.duplicate_subset if c in work.columns]
        work = work.drop_duplicates(subset=dedup_cols)
        duplicates_removed = before_dedup - len(work)

        work["dst_port"] = work["dst_port"].astype(int)
        work["pkt_size"] = work["pkt_size"].clip(lower=0)
        work["is_block"] = work["is_block"].astype(int)
        work["is_internal_src"] = work["src_ip"].map(self._is_private_ip).astype(int)
        work["is_internal_dst"] = work["dst_ip"].map(self._is_private_ip).astype(int)

        meta = {
            "input_rows": int(len(df)),
            "valid_rows": int(len(work)),
            "dropped_rows": dropped_rows,
            "duplicates_removed": int(duplicates_removed),
            "warnings": warnings,
        }
        for warning in warnings:
            logger.warning(warning)

        return work.reset_index(drop=True), meta

    def _apply_aliases(self, df: pd.DataFrame) -> pd.DataFrame:
        lowered = {str(col).lower(): col for col in df.columns}
        for canonical, aliases in self.config.column_aliases.items():
            if canonical in df.columns:
                continue
            for alias in aliases:
                source = lowered.get(alias.lower())
                if source is not None:
                    df[canonical] = df[source]
                    break
        return df

    def _coerce_block_flag(self, df: pd.DataFrame) -> pd.Series:
        if "action" in df.columns:
            action_block = df["action"].astype(str).str.lower().str.strip().isin(self.config.block_actions)
        else:
            action_block = pd.Series(False, index=df.index)

        raw = df["is_block"]
        if raw.dtype == bool:
            return raw | action_block

        raw_text = raw.astype(str).str.lower().str.strip()
        truthy = raw_text.isin(["1", "true", "yes", "y", "blocked", "block", "deny", "drop"])
        numeric = pd.to_numeric(raw, errors="coerce").fillna(0) > 0
        return truthy | numeric | action_block

    @staticmethod
    def _parse_timestamps(series: pd.Series) -> pd.Series:
        try:
            return pd.to_datetime(series, errors="coerce", utc=False, format="mixed")
        except TypeError:
            return pd.to_datetime(series, errors="coerce", utc=False)

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_private_ip(value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
            return bool(ip.is_private)
        except ValueError:
            return False


class FeatureEngineer:
    """Builds aggregate firewall features without fitting any model state."""

    def __init__(self, config: PipelineConfig | None = None):
        self.config = config or PipelineConfig()
        self.validator = FirewallLogValidator(self.config)

    def validate_logs(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, object]]:
        return self.validator.validate(df)

    def build_anomaly_features(self, df: pd.DataFrame, validate: bool = True) -> pd.DataFrame:
        if validate:
            df, _ = self.validate_logs(df)
        if df.empty:
            return pd.DataFrame(columns=["src_ip", "hour_window", "failed_attempts"] + FEATURE_COLUMNS)

        work = self._prepare_time_features(df)
        grouped = work.groupby(["src_ip", "hour_window"], observed=True)

        agg_df = grouped.agg(
            block_frequency=("is_block", "sum"),
            unique_ports_targeted=("dst_port", "nunique"),
            bytes_per_packet=("pkt_size_clean", "mean"),
            dst_ip_diversity=("dst_ip", "nunique"),
            avg_inter_event_time=("inter_event_time", "mean"),
            external_dst_ratio=("is_internal_dst", lambda s: 1.0 - float(s.mean())),
        ).reset_index()

        agg_df["bytes_per_packet"] = agg_df["bytes_per_packet"].fillna(self.config.default_packet_size)
        agg_df["avg_inter_event_time"] = agg_df["avg_inter_event_time"].fillna(
            self.config.default_inter_event_seconds
        )
        agg_df["event_hour"] = agg_df["hour_window"].dt.hour.astype(float)
        entropies = grouped["protocol"].apply(self._entropy_vectorized)
        agg_df = agg_df.merge(entropies.rename("protocol_entropy"), on=["src_ip", "hour_window"], how="left")
        agg_df["protocol_entropy"] = agg_df["protocol_entropy"].fillna(0.0)
        agg_df["hour_window"] = agg_df["hour_window"].astype(str)
        agg_df["failed_attempts"] = agg_df["block_frequency"]

        all_cols = ["src_ip", "hour_window", "failed_attempts"] + FEATURE_COLUMNS
        return self._finalize_numeric(agg_df, all_cols)

    def build_cluster_features(self, df: pd.DataFrame, validate: bool = True) -> pd.DataFrame:
        if validate:
            df, _ = self.validate_logs(df)
        if df.empty:
            return pd.DataFrame(columns=["src_ip"] + CLUSTER_FEATURE_COLUMNS)

        work = self._prepare_time_features(df)
        grouped = work.groupby("src_ip", observed=True)

        agg_df = grouped.agg(
            total_events=("timestamp", "count"),
            blocked_events=("is_block", "sum"),
            unique_ports=("dst_port", "nunique"),
            avg_bytes_per_packet=("pkt_size_clean", "mean"),
            dst_ip_diversity=("dst_ip", "nunique"),
            avg_inter_event_time=("inter_event_time", "mean"),
            external_dst_ratio=("is_internal_dst", lambda s: 1.0 - float(s.mean())),
        ).reset_index()

        agg_df["block_ratio"] = agg_df["blocked_events"] / agg_df["total_events"].clip(lower=1)
        agg_df["avg_bytes_per_packet"] = agg_df["avg_bytes_per_packet"].fillna(self.config.default_packet_size)
        agg_df["avg_inter_event_time"] = agg_df["avg_inter_event_time"].fillna(
            self.config.default_inter_event_seconds
        )

        off_hours = work[(work["event_hour"] < 6) | (work["event_hour"] >= 22)].groupby("src_ip").size()
        agg_df = agg_df.merge(off_hours.rename("off_hours_count"), on="src_ip", how="left")
        agg_df["off_hours_count"] = agg_df["off_hours_count"].fillna(0.0)
        agg_df["off_hours_ratio"] = agg_df["off_hours_count"] / agg_df["total_events"].clip(lower=1)

        agg_df["port_scan_score"] = np.where(
            agg_df["unique_ports"] >= self.config.port_scan_unique_ports,
            agg_df["unique_ports"] / agg_df["total_events"].clip(lower=1),
            0.0,
        )

        events_per_hour = work.groupby(["src_ip", "hour_window"], observed=True).size()
        burst_stats = events_per_hour.groupby("src_ip").agg(["std", "mean"])
        burst_series = (burst_stats["std"] / burst_stats["mean"].replace(0, np.nan)).fillna(0.0)
        agg_df = agg_df.merge(burst_series.rename("burst_index"), on="src_ip", how="left")
        agg_df["burst_index"] = agg_df["burst_index"].fillna(0.0)

        entropies = grouped["protocol"].apply(self._entropy_vectorized)
        agg_df = agg_df.merge(entropies.rename("protocol_entropy"), on="src_ip", how="left")
        agg_df["protocol_entropy"] = agg_df["protocol_entropy"].fillna(0.0)

        return self._finalize_numeric(agg_df, ["src_ip"] + CLUSTER_FEATURE_COLUMNS)

    def _prepare_time_features(self, df: pd.DataFrame) -> pd.DataFrame:
        work = df.copy().sort_values(["src_ip", "timestamp"])
        work["event_hour"] = work["timestamp"].dt.hour
        work["hour_window"] = work["timestamp"].dt.floor(self.config.timestamp_floor)
        work["pkt_size_clean"] = work["pkt_size"].replace(0, np.nan)
        work["inter_event_time"] = work.groupby("src_ip", observed=True)["timestamp"].diff().dt.total_seconds()
        return work

    @staticmethod
    def _entropy_vectorized(series: pd.Series) -> float:
        if series.empty:
            return 0.0
        probs = series.value_counts(normalize=True)
        return -float((probs * np.log2(probs)).sum())

    @staticmethod
    def _finalize_numeric(df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
        for col in columns:
            if col in ("src_ip", "hour_window"):
                continue
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
        return df[columns]
