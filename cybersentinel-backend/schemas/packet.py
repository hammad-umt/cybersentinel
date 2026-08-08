"""
schemas/packet.py

Pydantic v2 request and response models for the packet classification module.

Classify requests use the same 23-feature vector as cs-fyp (FEATURE_NAMES).
Display/SOC fields (IPs, port) are separate and are not passed to XGBoost.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator

from ml_engine.features import FEATURE_NAMES, PUBLIC_ATTACK_TYPES


# ---------------------------------------------------------------------------
# Request schemas — cs-fyp 23-feature vector + optional context
# ---------------------------------------------------------------------------

class FlowFeatureVector(BaseModel):
    """
    Canonical 23-feature flow vector — identical keys to cs-fyp ``FEATURE_NAMES``.

    All fields are optional at the HTTP layer; missing values are derived or
    zero-filled at inference time. Unknown keys are rejected (``extra=forbid``).
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    flow_duration: Optional[float] = Field(None, description="Flow duration (CICIDS microseconds)")
    total_fwd_packets: Optional[float] = None
    total_bwd_packets: Optional[float] = None
    total_length_fwd: Optional[float] = None
    total_length_bwd: Optional[float] = None
    fwd_packet_length_max: Optional[float] = None
    bwd_packet_length_max: Optional[float] = None
    flow_bytes_per_s: Optional[float] = None
    flow_packets_per_s: Optional[float] = None
    flow_iat_mean: Optional[float] = None
    flow_iat_std: Optional[float] = None
    fwd_iat_mean: Optional[float] = None
    bwd_iat_mean: Optional[float] = None
    syn_flag_count: Optional[float] = None
    ack_flag_count: Optional[float] = None
    fin_flag_count: Optional[float] = None
    rst_flag_count: Optional[float] = None
    psh_flag_count: Optional[float] = None
    urg_flag_count: Optional[float] = None
    down_up_ratio: Optional[float] = None
    avg_packet_size: Optional[float] = None
    unique_dest_ports: Optional[float] = None
    failed_connections: Optional[float] = None


class FlowInput(BaseModel):
    """Features for ML + optional metadata for display/SOC (not fed to XGBoost)."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    features: FlowFeatureVector
    source_ip: Optional[str] = Field(
        None,
        validation_alias=AliasChoices("source_ip", "src_ip"),
        description="Source IP — SOC/display only",
    )
    dest_ip: Optional[str] = Field(
        None,
        validation_alias=AliasChoices("dest_ip", "dst_ip"),
        description="Destination IP — SOC/display only",
    )
    dest_port: Optional[int] = Field(None, description="Destination port — SOC/display only")
    protocol: Optional[str] = Field("TCP", description="Protocol label — display only")


class PacketClassifyRequest(BaseModel):
    """
    Single-flow classification (cs-fyp aligned).

    Preferred body::

        {
          "source_ip": "10.0.0.1",
          "dest_ip": "8.8.8.8",
          "dest_port": 443,
          "protocol": "TCP",
          "features": { ... 23 keys from FEATURE_NAMES ... }
        }
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    features: FlowFeatureVector
    source_ip: Optional[str] = Field(None, validation_alias=AliasChoices("source_ip", "src_ip"))
    dest_ip: Optional[str] = Field(None, validation_alias=AliasChoices("dest_ip", "dst_ip"))
    dest_port: Optional[int] = None
    protocol: Optional[str] = "TCP"

    @model_validator(mode="before")
    @classmethod
    def _reject_non_feature_keys_in_features(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        features = data.get("features")
        if isinstance(features, dict):
            unknown = sorted(set(features.keys()) - set(FEATURE_NAMES))
            if unknown:
                raise ValueError(
                    f"features contains unknown keys {unknown}. "
                    f"Allowed: {FEATURE_NAMES}"
                )
        return data

    def to_flow_input(self) -> FlowInput:
        return FlowInput(
            features=self.features,
            source_ip=self.source_ip,
            dest_ip=self.dest_ip,
            dest_port=self.dest_port,
            protocol=self.protocol,
        )


class PacketBatchRequest(BaseModel):
    """Batch classification — list of cs-fyp flow payloads."""

    flows: List[PacketClassifyRequest] = Field(..., min_length=1, max_length=10_000)


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class PacketPrediction(BaseModel):
    """SOC-grade fused packet decision for one flow."""

    # Backward-compatible final SOC label (alias of soc_verdict)
    prediction: Literal["Normal", "Suspicious", "Malicious", "Insufficient Evidence"] = Field(
        description="Final fused SOC decision (same as soc_verdict)"
    )
    soc_verdict: Literal["Normal", "Suspicious", "Malicious", "Insufficient Evidence"] = Field(
        description="Final fused SOC 3-class verdict"
    )
    raw_model_prediction: str = Field(
        description="Granular XGBoost attack class (Benign, DDoS, PortScan, Botnet, etc.)"
    )
    raw_model_confidence: float = Field(0.0, ge=0.0, le=1.0, description="Confidence for raw_model_prediction")
    risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Final fused risk score")
    ml_model: Literal["xgboost"] = Field(default="xgboost")
    ml_prediction: Literal["Normal", "Suspicious", "Malicious", "Insufficient Evidence"] = Field(
        description="Collapsed XGBoost label before SOC fusion"
    )
    ml_confidence: float = Field(ge=0.0, le=1.0)
    ml_probabilities: dict[str, float] = Field(default_factory=dict)
    mitre_id: Optional[str] = Field(default=None, description="MITRE ATT&CK technique ID")
    mitre_technique: Optional[str] = Field(default=None, description="MITRE ATT&CK technique name")
    mitre_tactic: Optional[str] = Field(default=None, description="MITRE ATT&CK tactic")
    packet_anomaly_level: Literal["Normal", "Suspicious", "Malicious"] = "Normal"
    packet_anomaly_score: float = Field(0.0, ge=0.0, le=100.0)
    firewall_anomaly_level: Literal["Normal", "Suspicious", "Malicious"] = "Normal"
    firewall_anomaly_score: float = Field(0.0, ge=0.0, le=100.0)
    firewall_signal_source: Literal["none", "firewall_alert"] = "none"
    triggered_rules: List[str] = Field(default_factory=list)
    final_confidence: float = Field(ge=0.0, le=1.0)
    explanation: List[str] = Field(default_factory=list)

    prob_normal: Optional[float] = Field(default=None, exclude=True)
    prob_suspicious: Optional[float] = Field(default=None, exclude=True)
    prob_malicious: Optional[float] = Field(default=None, exclude=True)
    feature_coverage: Optional[float] = Field(default=None, exclude=True)
    missing_feature_count: Optional[int] = Field(default=None, exclude=True)
    traffic_schema: Optional[str] = Field(default=None, exclude=True)


class PacketClassifyResponse(BaseModel):
    success: bool = True
    result: PacketPrediction


class PacketBatchResponse(BaseModel):
    success: bool = True
    total_flows: int
    results: List[PacketPrediction]
    normal_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    insufficient_evidence_count: int = 0
    avg_risk_score: float = 0.0


class PacketEventOut(BaseModel):
    id: str
    timestamp: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    prediction: Literal["Normal", "Suspicious", "Malicious", "Insufficient Evidence"]
    raw_model_prediction: Optional[str] = None
    ml_confidence: float = Field(validation_alias="confidence")
    risk_score: float = Field(validation_alias="threat_score_contribution", ge=0.0, le=100.0)
    source: str

    model_config = {"from_attributes": True}


class PacketEventsResponse(BaseModel):
    success: bool = True
    total: int
    page: int
    page_size: int
    events: List[PacketEventOut]
