"""
schemas/capture.py

Pydantic v2 request and response models for live packet capture
and real-time Windows firewall log monitoring.

Flutter usage:
  POST /api/v1/capture/start         → body: CaptureStartRequest
                                     ← response: CaptureStatusResponse
  POST /api/v1/capture/stop          ← response: CaptureStatusResponse
  GET  /api/v1/capture/status        ← response: CaptureStatusResponse
  GET  /api/v1/capture/interfaces    ← response: InterfacesResponse
  GET  /api/v1/capture/packets       ← response: CapturedPacketsResponse
  POST /api/v1/capture/firewall/start  → body: FirewallMonitorRequest
                                       ← response: FirewallMonitorResponse
  POST /api/v1/capture/firewall/stop   ← response: FirewallMonitorResponse
"""

from __future__ import annotations

from typing import List, Literal, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Network interface info
# ---------------------------------------------------------------------------

class NetworkInterface(BaseModel):
    """One network interface available for packet capture."""
    index: int
    name: str
    description: str
    ip_addresses: List[str] = Field(default_factory=list)
    is_up: bool = True


class InterfacesResponse(BaseModel):
    success: bool = True
    interfaces: List[NetworkInterface]
    recommended_index: Optional[int] = Field(
        default=None,
        description="Best interface index for live capture (connected link with routable IP)",
    )
    tshark_available: bool = False
    scapy_available: bool = False


# ---------------------------------------------------------------------------
# Capture control
# ---------------------------------------------------------------------------

class CaptureStartRequest(BaseModel):
    """
    Flutter sends this to start live packet capture.

    Example:
    {
        "interface_index": 0,
        "packet_limit": 100,
        "timeout_seconds": 30,
        "bpf_filter": "tcp port 80 or tcp port 443"
    }
    """
    interface_index: int = Field(default=0, description="Index from /interfaces list")
    packet_limit: int = Field(default=10000, ge=1, le=10000, description="Max packets to capture")
    timeout_seconds: int = Field(
        default=86400,
        ge=5,
        le=86400,
        description="Auto-stop after N seconds (86400 = until user stops)",
    )
    bpf_filter: Optional[str] = Field(
        default=None,
        description="Optional BPF filter e.g. 'tcp port 80'"
    )
    use_tshark: bool = Field(default=False, description="Use TShark instead of Scapy")


class CaptureStatusResponse(BaseModel):
    success: bool = True
    is_running: bool
    engine: Optional[str] = None          # scapy | tshark | none
    interface: Optional[str] = None
    packets_captured: int = 0
    packets_classified: int = 0
    started_at: Optional[str] = None
    message: str = ""


# ---------------------------------------------------------------------------
# Captured packet results
# ---------------------------------------------------------------------------

class CapturedPacketResult(BaseModel):
    """One captured + classified packet flow."""
    packet_id: str
    timestamp: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    pkt_size: Optional[int] = None

    # ML classification result
    prediction: Literal["Normal", "Suspicious", "Malicious", "Insufficient Evidence", "Pending"]
    confidence: float = 0.0
    threat_score: float = 0.0

    # Flow features extracted
    features_extracted: int = 0


class CapturedPacketsResponse(BaseModel):
    success: bool = True
    total: int
    packets: List[CapturedPacketResult]
    normal_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    avg_threat_score: float = 0.0


# ---------------------------------------------------------------------------
# Firewall log monitor
# ---------------------------------------------------------------------------

class FirewallMonitorRequest(BaseModel):
    """
    Flutter sends this to start tailing the Windows firewall log in real time.

    Example:
    {
        "log_path": "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log",
        "poll_interval_seconds": 2
    }
    """
    log_path: Optional[str] = Field(
        default=None,
        description="Custom log path. Defaults to Windows pfirewall.log location."
    )
    poll_interval_seconds: int = Field(
        default=2, ge=1, le=60,
        description="How often to check for new log lines"
    )


class FirewallMonitorResponse(BaseModel):
    success: bool = True
    is_running: bool
    log_path: Optional[str] = None
    lines_processed: int = 0
    alerts_generated: int = 0
    message: str = ""