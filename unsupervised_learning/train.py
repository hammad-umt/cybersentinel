from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

from pipeline import UnsupervisedPipeline
from config import PipelineConfig
from windows_log_reader import find_default_firewall_log_paths, read_firewall_log


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train the unsupervised model on real Windows Firewall or Linux iptables/UFW logs."
    )
    parser.add_argument(
        "--log-path",
        action="append",
        dest="log_paths",
        help="Firewall log path. Repeat for multiple files. Defaults to detected OS firewall logs.",
    )
    parser.add_argument(
        "--source",
        choices=["auto", "windows", "iptables", "linux"],
        default="auto",
        help="Log format for every --log-path.",
    )
    parser.add_argument(
        "--clustering-algorithm",
        choices=["kmeans", "dbscan"],
        default="kmeans",
        help="Clustering algorithm to train and save",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    using_default_paths = not args.log_paths
    log_paths = [Path(path) for path in args.log_paths] if args.log_paths else find_default_firewall_log_paths()
    if not log_paths:
        raise FileNotFoundError(
            "No real firewall logs found. Pass --log-path for Windows pfirewall.log or Linux "
            "iptables/UFW logs such as /var/log/ufw.log."
        )

    frames = []
    read_errors = []
    for log_path in log_paths:
        print(f"Reading firewall log: {log_path}")
        try:
            frame = read_firewall_log(log_path, source=args.source)
        except PermissionError as exc:
            read_errors.append(f"{log_path}: permission denied")
            if not using_default_paths:
                raise PermissionError(_permission_help(log_path)) from exc
            print(f"Skipping unreadable firewall log: {log_path}")
            continue
        except ValueError as exc:
            read_errors.append(f"{log_path}: {exc}")
            if not using_default_paths:
                raise
            print(f"Skipping unsupported firewall log: {log_path} ({exc})")
            continue
        print(f"Loaded {len(frame)} usable entries from {log_path}")
        frames.append(frame)

    if not frames:
        details = "\n".join(f"- {error}" for error in read_errors) or "- no candidate logs were readable"
        raise PermissionError(
            "No readable firewall logs could be loaded.\n"
            f"{details}\n\n"
            f"{_permission_help(log_paths[0])}"
        )

    df = pd.concat(frames, ignore_index=True)
    if df.empty:
        raise ValueError("No usable firewall log rows were loaded; refusing to train on empty data.")

    config = PipelineConfig(clustering_algorithm=args.clustering_algorithm)
    pipeline = UnsupervisedPipeline(config)

    print(
        f"Training pipeline on {len(df)} real firewall log entries "
        f"(clustering={args.clustering_algorithm})..."
    )
    pipeline.fit(df)

    print("Saving models...")
    pipeline.save_pipeline()
    print(f"Saved to: {config.anomaly_model_path}")
    print(f"Saved to: {config.clustering_model_path}")
    if args.clustering_algorithm == "kmeans":
        legacy_path = Path(config.model_dir) / "clustering_model.joblib"
        if Path(config.clustering_model_path) != legacy_path:
            import shutil
            shutil.copy2(config.clustering_model_path, legacy_path)
            print(f"Saved legacy copy to: {legacy_path}")
    print("Done. You can now start the FastAPI server.")


def _permission_help(log_path: Path) -> str:
    return (
        f"Cannot read {log_path}. On Windows, run PowerShell as Administrator, or copy "
        "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log to a readable folder and run:\n"
        "python train.py --log-path C:\\path\\to\\pfirewall.log --source windows"
    )


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        print(f"\nTraining failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
