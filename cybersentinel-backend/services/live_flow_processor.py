"""
Bidirectional live flow aggregation for real-time capture.

Packets are accumulated in memory (never stored raw). When a flow completes,
features are exported in CICIDS2017-compatible units for the hybrid SOC pipeline.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

import numpy as np

from schemas.packet import FlowFeatureVector, FlowInput

FlowKey = Tuple[str, str, int, int, str]
OnFlowComplete = Callable[["LiveFlowState"], None]

_US_PER_SECOND = 1_000_000.0


def _canonical_flow_key(
    src_ip: str,
    dst_ip: str,
    src_port: int | None,
    dst_port: int | None,
    protocol: str,
) -> tuple[FlowKey, bool]:
    """Normalize 5-tuple so both directions map to one flow. Returns (key, is_forward)."""
    sport = int(src_port or 0)
    dport = int(dst_port or 0)
    a = (src_ip, sport)
    b = (dst_ip, dport)
    if a <= b:
        return (src_ip, dst_ip, sport, dport, protocol.upper()), True
    return (dst_ip, src_ip, dport, sport, protocol.upper()), False


@dataclass
class LiveFlowState:
    flow_id: str
    fwd_ip: str
    bwd_ip: str
    fwd_port: int
    bwd_port: int
    protocol: str
    start_time: float = 0.0
    last_seen: float = 0.0
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    fwd_lengths: List[int] = field(default_factory=list)
    bwd_lengths: List[int] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    fwd_timestamps: List[float] = field(default_factory=list)
    bwd_timestamps: List[float] = field(default_factory=list)
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    failed_connections: int = 0
    saw_fin: bool = False
    saw_rst: bool = False

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    def update(
        self,
        *,
        timestamp: float,
        packet_size: int,
        direction_fwd: bool,
        flags: dict[str, bool] | None = None,
    ) -> None:
        if self.start_time == 0.0:
            self.start_time = timestamp
        self.last_seen = timestamp
        self.timestamps.append(timestamp)

        if direction_fwd:
            self.fwd_packets += 1
            self.fwd_bytes += packet_size
            self.fwd_lengths.append(packet_size)
            self.fwd_timestamps.append(timestamp)
        else:
            self.bwd_packets += 1
            self.bwd_bytes += packet_size
            self.bwd_lengths.append(packet_size)
            self.bwd_timestamps.append(timestamp)

        if flags:
            if flags.get("SYN"):
                self.syn_count += 1
            if flags.get("ACK"):
                self.ack_count += 1
            if flags.get("FIN"):
                self.fin_count += 1
                self.saw_fin = True
            if flags.get("RST"):
                self.rst_count += 1
                self.saw_rst = True
            if flags.get("PSH"):
                self.psh_count += 1
            if flags.get("URG"):
                self.urg_count += 1
            if flags.get("RST"):
                self.failed_connections += 1

    def should_complete(self, idle_seconds: float) -> bool:
        if self.total_packets == 0:
            return False
        if self.saw_rst:
            return True
        if self.saw_fin and self.fwd_packets > 0 and self.bwd_packets > 0:
            return True
        return (time.time() - self.last_seen) >= idle_seconds

    def to_flow_input(self) -> FlowInput:
        """Export cs-fyp 23-feature vector for PacketService / XGBoost."""
        duration_s = max(self.last_seen - self.start_time, 0.001)
        duration_us = duration_s * _US_PER_SECOND
        total_packets = max(self.total_packets, 1)
        total_bytes = self.fwd_bytes + self.bwd_bytes

        all_iats = np.diff(self.timestamps) if len(self.timestamps) > 1 else np.array([0.0])
        fwd_iats = np.diff(self.fwd_timestamps) if len(self.fwd_timestamps) > 1 else np.array([0.0])
        bwd_iats = np.diff(self.bwd_timestamps) if len(self.bwd_timestamps) > 1 else np.array([0.0])

        fwd_max = float(max(self.fwd_lengths) if self.fwd_lengths else 0)
        bwd_max = float(max(self.bwd_lengths) if self.bwd_lengths else 0)
        avg_pkt = total_bytes / total_packets

        features = FlowFeatureVector(
            flow_duration=duration_us,
            total_fwd_packets=float(self.fwd_packets),
            total_bwd_packets=float(self.bwd_packets),
            total_length_fwd=float(self.fwd_bytes),
            total_length_bwd=float(self.bwd_bytes),
            fwd_packet_length_max=fwd_max,
            bwd_packet_length_max=bwd_max,
            flow_bytes_per_s=total_bytes / duration_s,
            flow_packets_per_s=total_packets / duration_s,
            flow_iat_mean=float(np.mean(all_iats)) * _US_PER_SECOND,
            flow_iat_std=float(np.std(all_iats)) * _US_PER_SECOND,
            fwd_iat_mean=float(np.mean(fwd_iats)) * _US_PER_SECOND if len(fwd_iats) else 0.0,
            bwd_iat_mean=float(np.mean(bwd_iats)) * _US_PER_SECOND if len(bwd_iats) else 0.0,
            syn_flag_count=float(self.syn_count),
            ack_flag_count=float(self.ack_count),
            fin_flag_count=float(self.fin_count),
            rst_flag_count=float(self.rst_count),
            psh_flag_count=float(self.psh_count),
            urg_flag_count=float(self.urg_count),
            down_up_ratio=self.bwd_bytes / max(self.fwd_bytes, 1),
            avg_packet_size=avg_pkt,
            unique_dest_ports=1.0,
            failed_connections=float(self.failed_connections),
        )
        return FlowInput(
            features=features,
            source_ip=self.fwd_ip,
            dest_ip=self.bwd_ip,
            dest_port=self.bwd_port or None,
            protocol=self.protocol,
        )

    def to_flow_features(self) -> FlowInput:
        """Backward-compatible alias."""
        return self.to_flow_input()


class LiveFlowProcessor:
    """In-memory flow aggregator — one instance per capture session."""

    def __init__(
        self,
        on_flow_complete: OnFlowComplete | None = None,
        *,
        idle_timeout_seconds: float | None = None,
        max_flows: int | None = None,
        min_packets: int | None = None,
    ):
        from core.config import settings

        self.idle_timeout_seconds = idle_timeout_seconds or settings.LIVE_FLOW_TIMEOUT_SECONDS
        self.max_flows = max_flows or settings.LIVE_FLOW_MAX_IN_MEMORY
        self.min_packets = min_packets or settings.LIVE_FLOW_MIN_PACKETS
        self.on_flow_complete = on_flow_complete
        self._flows: Dict[FlowKey, LiveFlowState] = {}

    def ingest(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        src_port: int | None,
        dst_port: int | None,
        protocol: str,
        packet_size: int,
        timestamp: float | None = None,
        flags: dict[str, bool] | None = None,
    ) -> LiveFlowState | None:
        ts = timestamp if timestamp is not None else time.time()
        key, is_fwd = _canonical_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

        if key not in self._flows:
            if len(self._flows) >= self.max_flows:
                self._evict_oldest()
            fwd_ip, bwd_ip, fwd_port, bwd_port, proto = key
            self._flows[key] = LiveFlowState(
                flow_id=str(uuid.uuid4())[:12],
                fwd_ip=fwd_ip,
                bwd_ip=bwd_ip,
                fwd_port=fwd_port,
                bwd_port=bwd_port,
                protocol=proto,
            )

        flow = self._flows[key]
        flow.update(
            timestamp=ts,
            packet_size=packet_size,
            direction_fwd=is_fwd,
            flags=flags,
        )

        if flow.should_complete(self.idle_timeout_seconds):
            return self._complete(key)
        return None

    def flush_expired(self) -> List[LiveFlowState]:
        now = time.time()
        expired = [k for k, f in self._flows.items() if (now - f.last_seen) >= self.idle_timeout_seconds]
        completed: List[LiveFlowState] = []
        for key in expired:
            flow = self._complete(key)
            if flow:
                completed.append(flow)
        return completed

    def flush_all(self) -> List[LiveFlowState]:
        keys = list(self._flows.keys())
        completed: List[LiveFlowState] = []
        for key in keys:
            flow = self._complete(key)
            if flow:
                completed.append(flow)
        return completed

    def _evict_oldest(self) -> None:
        if not self._flows:
            return
        oldest_key = min(self._flows, key=lambda k: self._flows[k].last_seen)
        self._complete(oldest_key)

    def _complete(self, key: FlowKey) -> LiveFlowState | None:
        flow = self._flows.pop(key, None)
        if flow is None:
            return None
        if flow.total_packets < self.min_packets:
            return None
        if self.on_flow_complete:
            self.on_flow_complete(flow)
        return flow

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)
