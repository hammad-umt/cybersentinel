"""Smoke-test the saved CyberSentinel supervised classifier."""

from pathlib import Path

import pandas as pd

from model import CyberSentinelPacketClassifier


MODEL_DIR = Path("models")
SAMPLE_CSV = Path("dataset/Monday-WorkingHours.pcap_ISCX.csv")


def main() -> None:
    classifier = CyberSentinelPacketClassifier.load_model(MODEL_DIR)
    flows = pd.read_csv(SAMPLE_CSV, low_memory=False).head(5)
    predictions = classifier.predict(flows)
    live_flow = pd.DataFrame(
        [
            {
                "duration": 1.25,
                "orig_pkts": 18,
                "resp_pkts": 14,
                "orig_ip_bytes": 3200,
                "resp_ip_bytes": 2800,
                "tcp.syn": 1,
                "tcp.ack": 30,
                "tcp.fin": 1,
                "tcp.rst": 0,
                "tcp.psh": 4,
                "tcp.urg": 0,
                "tcp.psh_toserver": 1,
                "tcp.urg_toserver": 0,
                "flow_iat_mean": 39062.5,
                "flow_iat_std": 10000.0,
                "orig_iat_mean": 73529.4,
                "resp_iat_mean": 96153.8,
                "packet_length_std": 42.0,
                "tcp.window_size_toserver": 8192,
                "tcp.window_size_toclient": 8192,
                "active_mean": 1250000.0,
                "idle_mean": 0.0,
            }
        ]
    )
    live_prediction = classifier.predict(live_flow)
    print(predictions.to_string(index=False))
    print("\nLive-flow adapter smoke test:")
    print(live_prediction.to_string(index=False))


if __name__ == "__main__":
    main()
