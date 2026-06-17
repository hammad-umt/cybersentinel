"""
schemas/packet.py

Pydantic v2 request and response models for the packet classification module.

These define exactly what JSON Flutter sends to the backend and exactly
what JSON the backend sends back. If a field doesn't match, FastAPI
automatically returns a 422 Unprocessable Entity with a clear error message.

Flutter usage:
  POST /api/v1/packet/classify       → body: PacketClassifyRequest
                                     ← response: PacketClassifyResponse
  POST /api/v1/packet/classify/batch ← response: PacketBatchResponse
  GET  /api/v1/packet/events         ← response: List[PacketEventOut]
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Request schemas — what Flutter sends IN
# ---------------------------------------------------------------------------

class FlowFeatures(BaseModel):
    """
    One network flow record.
    Field names match CICIDS2017 column names that your supervised model expects.
    All fields are optional. The service accepts partial live flows, but the
    classifier returns Insufficient Evidence when coverage is too low for a
    trustworthy security verdict.
    """

    # Flow-level timing
    flow_duration: Optional[float] = Field(None, alias="Flow Duration")
    flow_iat_mean: Optional[float] = Field(None, alias="Flow IAT Mean")
    flow_iat_std: Optional[float] = Field(None, alias="Flow IAT Std")
    fwd_iat_mean: Optional[float] = Field(None, alias="Fwd IAT Mean")
    bwd_iat_mean: Optional[float] = Field(None, alias="Bwd IAT Mean")

    # Packet counts
    total_fwd_packets: Optional[float] = Field(None, alias="Total Fwd Packets")
    total_bwd_packets: Optional[float] = Field(None, alias="Total Backward Packets")

    # Byte counts
    total_len_fwd: Optional[float] = Field(None, alias="Total Length of Fwd Packets")
    total_len_bwd: Optional[float] = Field(None, alias="Total Length of Bwd Packets")

    # Packet length stats
    fwd_pkt_len_mean: Optional[float] = Field(None, alias="Fwd Packet Length Mean")
    bwd_pkt_len_mean: Optional[float] = Field(None, alias="Bwd Packet Length Mean")
    pkt_len_mean: Optional[float] = Field(None, alias="Packet Length Mean")
    pkt_len_std: Optional[float] = Field(None, alias="Packet Length Std")

    # Flow rates
    flow_bytes_per_s: Optional[float] = Field(None, alias="Flow Bytes/s")
    flow_pkts_per_s: Optional[float] = Field(None, alias="Flow Packets/s")
    fwd_pkts_per_s: Optional[float] = Field(None, alias="Fwd Packets/s")
    bwd_pkts_per_s: Optional[float] = Field(None, alias="Bwd Packets/s")

    # TCP flags
    fin_flag_count: Optional[float] = Field(None, alias="FIN Flag Count")
    syn_flag_count: Optional[float] = Field(None, alias="SYN Flag Count")
    rst_flag_count: Optional[float] = Field(None, alias="RST Flag Count")
    psh_flag_count: Optional[float] = Field(None, alias="PSH Flag Count")
    ack_flag_count: Optional[float] = Field(None, alias="ACK Flag Count")
    urg_flag_count: Optional[float] = Field(None, alias="URG Flag Count")
    fwd_psh_flags: Optional[float] = Field(None, alias="Fwd PSH Flags")
    fwd_urg_flags: Optional[float] = Field(None, alias="Fwd URG Flags")

    # Segment sizes
    avg_fwd_segment_size: Optional[float] = Field(None, alias="Avg Fwd Segment Size")
    avg_bwd_segment_size: Optional[float] = Field(None, alias="Avg Bwd Segment Size")
    average_packet_size: Optional[float] = Field(None, alias="Average Packet Size")

    # TCP window sizes
    init_win_bytes_fwd: Optional[float] = Field(None, alias="Init_Win_bytes_forward")
    init_win_bytes_bwd: Optional[float] = Field(None, alias="Init_Win_bytes_backward")

    # Active / idle
    active_mean: Optional[float] = Field(None, alias="Active Mean")
    idle_mean: Optional[float] = Field(None, alias="Idle Mean")

    # Optional metadata — NOT fed to ML, used for display in Flutter
    src_ip: Optional[str] = Field(None, description="Source IP for display only")
    dst_ip: Optional[str] = Field(None, description="Destination IP for display only")
    dst_port: Optional[int] = Field(None, description="Destination port for display only")
    protocol: Optional[str] = Field(None, description="Protocol for display only")

    model_config = {
        "populate_by_name": True,  # accept both alias and field name
        "extra": "allow",         # preserve Zeek/Suricata/live-flow aliases
    }


class PacketClassifyRequest(BaseModel):
    """Single flow classification request from Flutter."""

    flow: FlowFeatures
    model_type: Optional[Literal["random_forest", "decision_tree", "svm"]] = Field(
        default=None,
        description="Optional classifier type; defaults to random_forest when omitted",
    )


class PacketBatchRequest(BaseModel):
    """
    Batch classification — Flutter sends a list of flows.
    Used when the user uploads a CSV in the UI.
    Max 10,000 flows per request to avoid memory issues.
    """
    flows: List[FlowFeatures] = Field(..., min_length=1, max_length=10_000)


# ---------------------------------------------------------------------------
# Response schemas — what the backend sends BACK to Flutter
# ---------------------------------------------------------------------------

class PacketPrediction(BaseModel):
    """
    ML result for one flow.
    Flutter uses 'prediction' to colour-code the row in the UI table.
    """
    prediction: Literal["Normal", "Suspicious", "Malicious", "Insufficient Evidence"] = Field(
        description="Normal | Suspicious | Malicious | Insufficient Evidence"
    )
    confidence: float = Field(
        description="Confidence of the top prediction (0.0 – 1.0)"
    )

    # Per-class probabilities — Flutter can use these for a bar chart
    prob_normal: Optional[float] = None
    prob_suspicious: Optional[float] = None
    prob_malicious: Optional[float] = None

    # Feature coverage tells Flutter how reliable this prediction is
    feature_coverage: Optional[float] = Field(
        None,
        description="Fraction of expected features that were present (0.0 – 1.0)"
    )
    missing_feature_count: Optional[int] = None
    traffic_schema: Optional[str] = Field(
        None,
        description="cicflowmeter-compatible | partially-derived-live-flow | insufficient-live-flow-features"
    )

    # Threat score contribution fed into ensemble (0-100)
    threat_score_contribution: float = Field(
        0.0,
        description="How much this packet result contributes to the overall threat score"
    )

    # DB record ID — Flutter uses this to link to the detail view
    event_id: Optional[str] = None


class PacketClassifyResponse(BaseModel):
    """Response for single flow classification."""
    success: bool = True
    result: PacketPrediction
    # Metadata
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None


class PacketBatchResponse(BaseModel):
    """Response for batch CSV classification."""
    success: bool = True
    total_flows: int
    results: List[PacketPrediction]

    # Summary counts — Flutter uses these for the pie chart on the dashboard
    normal_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    insufficient_evidence_count: int = 0

    # Average threat score across all flows in this batch
    avg_threat_score: float = 0.0


class PacketEventOut(BaseModel):
    """
    One row from the packet_events DB table.
    Used by GET /api/v1/packet/events for the Flutter history table.
    """
    id: str
    timestamp: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    prediction: Literal["Normal", "Suspicious", "Malicious", "Insufficient Evidence"]
    confidence: float
    threat_score_contribution: float
    source: str

    model_config = {"from_attributes": True}  # allows ORM model → Pydantic


class PacketEventsResponse(BaseModel):
    """Paginated list of past packet classification events."""
    success: bool = True
    total: int
    page: int
    page_size: int
    events: List[PacketEventOut]
