"""Shared test data and assertion helpers."""

from __future__ import annotations

from typing import Any

SAMPLE_FLOW = {
    "Flow Duration": 1_200_000,
    "Total Fwd Packets": 6,
    "Total Backward Packets": 5,
    "Total Length of Fwd Packets": 400,
    "Total Length of Bwd Packets": 900,
    "Fwd Packet Length Max": 80,
    "Fwd Packet Length Min": 20,
    "Fwd Packet Length Mean": 50.0,
    "Fwd Packet Length Std": 15.0,
    "Bwd Packet Length Max": 200,
    "Bwd Packet Length Min": 40,
    "Bwd Packet Length Mean": 120.0,
    "Bwd Packet Length Std": 40.0,
    "src_ip": "10.0.0.1",
    "dst_ip": "8.8.8.8",
    "dst_port": 443,
    "protocol": "TCP",
}

SPARSE_FLOW = {"src_ip": "1.2.3.4"}

IPTABLES_LOG_CONTENT = (
    "Jun 09 14:01:05 host kernel: [UFW BLOCK] "
    "IN=eth0 OUT= MAC= SRC=192.168.1.99 DST=10.0.0.5 LEN=64 "
    "TOS=0x00 PREC=0x00 TTL=64 ID=54321 PROTO=TCP SPT=51515 DPT=22\n"
    "Jun 09 14:01:06 host kernel: [UFW ALLOW] "
    "IN=eth0 OUT= MAC= SRC=192.168.1.10 DST=8.8.8.8 LEN=128 "
    "TOS=0x00 PREC=0x00 TTL=64 ID=54322 PROTO=UDP SPT=54321 DPT=53\n"
)

FIREWALL_INGEST_EVENT = {
    "timestamp": "2026-06-12 14:01:05",
    "src_ip": "192.168.1.99",
    "dst_ip": "10.0.0.5",
    "dst_port": 22,
    "protocol": "TCP",
    "pkt_size": 64,
    "action": "deny",
}

BATCH_CSV = (
    "Flow Duration,Total Fwd Packets,Total Backward Packets,"
    "Total Length of Fwd Packets,Total Length of Bwd Packets\n"
    "1200000,6,5,400,900\n"
)


def assert_success(body: dict[str, Any]) -> None:
    assert body.get("success") is True, body


def assert_failure_status(status_code: int, expected: int, response_text: str = "") -> None:
    assert status_code == expected, f"expected HTTP {expected}, got {status_code}: {response_text}"
