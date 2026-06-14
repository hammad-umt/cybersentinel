from __future__ import annotations

import random
import tempfile
from pathlib import Path

from config import PipelineConfig
from pipeline import UnsupervisedPipeline
from windows_log_reader import read_firewall_log, read_iptables_firewall_log


def _iptables_line(
    hour: int,
    minute: int,
    second: int,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    packet_size: int,
    action: str = "ACCEPT",
) -> str:
    prefix = "UFW ALLOW" if action == "ACCEPT" else "UFW BLOCK"
    return (
        f"Jun 09 {hour:02d}:{minute:02d}:{second:02d} host kernel: [{prefix}] "
        f"IN=eth0 OUT= MAC= SRC={src_ip} DST={dst_ip} LEN={packet_size} "
        f"TOS=0x00 PREC=0x00 TTL=64 ID=54321 PROTO={protocol} SPT=51515 DPT={dst_port}"
    )


def _write_iptables_fixture(path: Path, attack: bool = False) -> None:
    random.seed(42 if not attack else 99)
    lines = []

    if not attack:
        for hour in range(24):
            for src_ip in ["192.168.1.10", "192.168.1.11", "192.168.1.12"]:
                for _ in range(random.randint(3, 8)):
                    lines.append(
                        _iptables_line(
                            hour=hour,
                            minute=random.randint(0, 59),
                            second=random.randint(0, 59),
                            src_ip=src_ip,
                            dst_ip=f"8.8.8.{random.randint(1, 10)}",
                            dst_port=random.choice([53, 80, 443]),
                            protocol=random.choice(["TCP", "UDP"]),
                            packet_size=random.randint(100, 1500),
                        )
                    )
    else:
        for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 8080]:
            lines.append(
                _iptables_line(
                    hour=13,
                    minute=1,
                    second=port % 60,
                    src_ip="192.168.1.99",
                    dst_ip="10.0.0.5",
                    dst_port=port,
                    protocol="TCP",
                    packet_size=64,
                    action="DROP",
                )
            )
        for _ in range(5):
            lines.append(
                _iptables_line(
                    hour=13,
                    minute=random.randint(0, 59),
                    second=random.randint(0, 59),
                    src_ip="192.168.1.10",
                    dst_ip="8.8.8.8",
                    dst_port=443,
                    protocol="TCP",
                    packet_size=random.randint(300, 900),
                )
            )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        train_log = temp_path / "iptables-baseline.log"
        inference_log = temp_path / "iptables-live.log"
        _write_iptables_fixture(train_log)
        _write_iptables_fixture(inference_log, attack=True)

        train_df = read_firewall_log(train_log, source="iptables")
        inference_df = read_iptables_firewall_log(inference_log)
        assert not train_df.empty, "Parser did not load baseline iptables logs"
        assert not inference_df.empty, "Parser did not load inference iptables logs"
        assert {"timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "pkt_size", "is_block"}.issubset(
            train_df.columns
        )

        config = PipelineConfig(model_dir=str(temp_path / "models"))
        pipeline = UnsupervisedPipeline(config)

        print("Training unsupervised pipeline on parsed iptables firewall logs...")
        pipeline.fit(train_df)
        pipeline.save_pipeline()

        loaded_pipeline = UnsupervisedPipeline(config)
        loaded_pipeline.load_pipeline()
        results = loaded_pipeline.predict(inference_df)

        anomaly_df = results["anomaly_df"]
        cluster_df = results["cluster_df"]
        threat_signals = results["threat_signals"]

        assert not anomaly_df.empty, "No anomaly scores returned"
        assert not cluster_df.empty, "No cluster scores returned"
        assert "192.168.1.99" in set(cluster_df["src_ip"]), "Attack source IP was not scored"
        assert any(signal["src_ip"] == "192.168.1.99" for signal in threat_signals), (
            "Expected threat signal for blocked port scan"
        )

        print("\n===== ANOMALY DETECTION RESULTS =====")
        print(anomaly_df[["src_ip", "hour_window", "anomaly_score", "severity", "consensus_anomaly"]])

        print("\n===== BEHAVIOR CLUSTERING RESULTS =====")
        print(cluster_df[["src_ip", "total_events", "block_ratio", "unique_ports", "cluster_interpretation"]])

        print("\n===== CONSOLIDATED THREAT SIGNALS =====")
        for signal in threat_signals:
            print(signal)


if __name__ == "__main__":
    main()
