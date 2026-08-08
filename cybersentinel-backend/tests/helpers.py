"""Shared test data and assertion helpers."""

from __future__ import annotations

from typing import Any

SAMPLE_FLOW = {
    "source_ip": "10.0.0.1",
    "dest_ip": "8.8.8.8",
    "dest_port": 443,
    "protocol": "TCP",
    "features": {
        "flow_duration": 1_200_000,
        "total_fwd_packets": 6,
        "total_bwd_packets": 5,
        "total_length_fwd": 400,
        "total_length_bwd": 900,
        "fwd_packet_length_max": 80,
        "bwd_packet_length_max": 200,
        "flow_bytes_per_s": 1083.33,
        "flow_packets_per_s": 9.17,
        "flow_iat_mean": 120000.0,
        "flow_iat_std": 40000.0,
        "fwd_iat_mean": 100000.0,
        "bwd_iat_mean": 140000.0,
        "syn_flag_count": 1,
        "ack_flag_count": 10,
        "fin_flag_count": 1,
        "rst_flag_count": 0,
        "psh_flag_count": 4,
        "urg_flag_count": 0,
        "down_up_ratio": 2.25,
        "avg_packet_size": 118.18,
        "unique_dest_ports": 1,
        "failed_connections": 0,
    },
}

SPARSE_FLOW = {
    "source_ip": "1.2.3.4",
    "features": {},
}

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
    "flow_duration,total_fwd_packets,total_bwd_packets,total_length_fwd,total_length_bwd\n"
    "1200000,6,5,400,900\n"
)


def assert_success(body: dict[str, Any]) -> None:
    assert body.get("success") is True, body


def assert_failure_status(status_code: int, expected: int, response_text: str = "") -> None:
    assert status_code == expected, f"expected HTTP {expected}, got {status_code}: {response_text}"
