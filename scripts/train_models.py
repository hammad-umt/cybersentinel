#!/usr/bin/env python3
"""
Train CyberSentinel packet ML models from CICIDS2017 CSV data.

Usage (from repo root):
    python scripts/train_models.py
    python scripts/train_models.py --data supervised_learning/dataset --verbose
    python scripts/train_models.py --benign-ratio 3.0

Dataset:  supervised_learning/dataset/*.csv  (CICIDS2017 files)
Output:   supervised_learning/models/
          - supervised_model.joblib
          - unsupervised_model.joblib
          - scaler.joblib
          - training_report.json

After training, restart the backend or POST /api/v1/admin/reload-models (admin JWT).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from supervised_learning.train.pipeline import train_from_dataset  # noqa: E402

DEFAULT_DATA = REPO_ROOT / "supervised_learning" / "dataset"
DEFAULT_MODELS = REPO_ROOT / "supervised_learning" / "models"
DEFAULT_PROCESSED = REPO_ROOT / "supervised_learning" / "processed"


def main() -> int:
    parser = argparse.ArgumentParser(description="Train CyberSentinel XGBoost + Isolation Forest models")
    parser.add_argument(
        "--data",
        type=Path,
        default=DEFAULT_DATA,
        help=f"CICIDS CSV file or directory (default: {DEFAULT_DATA})",
    )
    parser.add_argument(
        "--models",
        type=Path,
        default=DEFAULT_MODELS,
        help=f"Output directory for .joblib artifacts (default: {DEFAULT_MODELS})",
    )
    parser.add_argument(
        "--processed",
        type=Path,
        default=DEFAULT_PROCESSED,
        help=f"Preprocessed numpy artifacts (default: {DEFAULT_PROCESSED})",
    )
    parser.add_argument(
        "--benign-ratio",
        type=float,
        default=3.0,
        help="Max Benign:Attack ratio after undersampling (default: 3.0)",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if not args.data.exists():
        print(
            f"ERROR: Dataset not found at {args.data}\n"
            "Place CICIDS2017 CSV files in supervised_learning/dataset/",
            file=sys.stderr,
        )
        return 1

    report = train_from_dataset(
        data_path=args.data,
        processed_dir=args.processed,
        models_dir=args.models,
        benign_max_ratio=args.benign_ratio,
    )

    sup = report["supervised"]
    unsup = report["unsupervised"]
    binary = sup.get("binary_attack_detection", {})

    print("\n=== CyberSentinel Training Complete ===")
    print(f"Supervised model:   {args.models / 'supervised_model.joblib'}")
    print(f"Unsupervised model: {args.models / 'unsupervised_model.joblib'}")
    print(f"Scaler:             {args.models / 'scaler.joblib'}")
    print(f"Report:             {args.models / 'training_report.json'}")
    print("\n--- Supervised (XGBoost) ---")
    print(f"Accuracy:           {sup.get('accuracy', 0):.4f}")
    print(f"F1 (weighted):      {sup.get('f1_weighted', 0):.4f}")
    print(f"ROC-AUC (binary):   {binary.get('roc_auc')}")
    print(f"False Positive Rate:{binary.get('false_positive_rate', 0):.4f}")
    print(f"False Negative Rate:{binary.get('false_negative_rate', 0):.4f}")
    print("\n--- Unsupervised (Isolation Forest) ---")
    print(f"False Positive Rate:{unsup.get('false_positive_rate', 0):.4f}")
    print(f"False Negative Rate:{unsup.get('false_negative_rate', 0):.4f}")
    print("\nRestart backend or: POST /api/v1/admin/reload-models")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
