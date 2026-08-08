"""Map flow records to the canonical 23-feature matrix."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from ml_engine.features import (
    COLUMN_ALIASES,
    FEATURE_NAMES,
    MIN_PRODUCTION_FEATURE_COVERAGE,
)


def _first_present(row: pd.Series, aliases: list[str]) -> float | None:
    for name in aliases:
        if name in row.index:
            value = row[name]
            if value is not None and not (isinstance(value, float) and np.isnan(value)):
                try:
                    return float(value)
                except (TypeError, ValueError):
                    continue
    return None


def _resolve_feature(row: pd.Series, fname: str) -> float | None:
    if fname in row.index:
        value = row[fname]
        if value is not None and not (isinstance(value, float) and np.isnan(value)):
            try:
                return float(value)
            except (TypeError, ValueError):
                return None
    if fname in COLUMN_ALIASES:
        return _first_present(row, COLUMN_ALIASES[fname])
    return None


def flows_to_feature_matrix(flows: pd.DataFrame) -> tuple[np.ndarray, pd.DataFrame]:
    """Convert flow DataFrame → (n_samples, 23) matrix + compatibility metadata."""
    rows = []
    compat_rows = []

    for _, flow in flows.iterrows():
        features: dict[str, float | None] = {}
        present = 0
        missing: list[str] = []

        for fname in FEATURE_NAMES:
            val = _resolve_feature(flow, fname)
            features[fname] = val
            if val is not None:
                present += 1
            else:
                missing.append(fname)

        fwd = features.get("total_length_fwd") or 0.0
        bwd = features.get("total_length_bwd") or 0.0
        if features.get("down_up_ratio") is None and (fwd or bwd):
            features["down_up_ratio"] = bwd / max(fwd, 1.0)
            if "down_up_ratio" in missing:
                missing.remove("down_up_ratio")
                present += 1

        fwd_pkts = features.get("total_fwd_packets") or 0.0
        bwd_pkts = features.get("total_bwd_packets") or 0.0
        total_pkts = fwd_pkts + bwd_pkts
        total_bytes = (fwd or 0.0) + (bwd or 0.0)
        if features.get("avg_packet_size") is None and total_pkts > 0:
            features["avg_packet_size"] = total_bytes / total_pkts
            if "avg_packet_size" in missing:
                missing.remove("avg_packet_size")
                present += 1

        if features.get("unique_dest_ports") is None:
            features["unique_dest_ports"] = 1.0
            if "unique_dest_ports" in missing:
                missing.remove("unique_dest_ports")
                present += 1

        if features.get("failed_connections") is None:
            rst = features.get("rst_flag_count") or 0.0
            features["failed_connections"] = float(rst) if rst > 5 else 0.0
            if "failed_connections" in missing:
                missing.remove("failed_connections")
                present += 1

        vector = [float(features.get(n) or 0.0) for n in FEATURE_NAMES]
        rows.append(vector)
        coverage = present / len(FEATURE_NAMES)
        compat_rows.append(
            {
                "feature_coverage": coverage,
                "missing_feature_count": len(missing),
                "missing_features": ",".join(missing[:8]),
                "traffic_schema": "cicids_live" if coverage >= MIN_PRODUCTION_FEATURE_COVERAGE else "partial",
            }
        )

    X = np.array(rows, dtype=np.float64)
    X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)
    compatibility = pd.DataFrame(compat_rows, index=flows.index)
    return X, compatibility


def csv_row_to_feature_vector(row: dict[str, object]) -> dict[str, float | None]:
    """Map a CSV row (canonical or legacy CICIDS headers) → 23-feature dict."""
    series = pd.Series(row)
    return {fname: _resolve_feature(series, fname) for fname in FEATURE_NAMES}


def load_training_report(model_dir: Path) -> dict:
    path = model_dir / "training_report.json"
    if path.exists():
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}
