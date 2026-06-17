"""
schemas/firewall.py

Pydantic v2 request and response models for the firewall log analysis module.

Flutter usage:
  POST /api/v1/firewall/analyze      → body: multipart file upload
                                     ← response: FirewallAnalyzeResponse
  POST /api/v1/firewall/ingest       → body: FirewallIngestRequest
                                     ← response: FirewallIngestResponse
  GET  /api/v1/firewall/alerts       ← response: FirewallAlertsResponse
  PATCH /api/v1/firewall/alerts/{id}/acknowledge ← response: AckResponse
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request schemas — what Flutter sends IN
# ---------------------------------------------------------------------------

class FirewallIngestRequest(BaseModel):
    """
    Single real-time firewall event sent by Flutter.
    Accepts a flat dict of key-value pairs — your RealtimeFirewallLogBuffer
    already handles alias normalization so Flutter doesn't need to use
    exact canonical field names.

    Example Flutter payload:
    {
        "event": {
            "timestamp": "2026-06-12 14:01:05",
            "src_ip": "192.168.1.99",
            "dst_ip": "10.0.0.5",
            "dst_port": 22,
            "protocol": "TCP",
            "pkt_size": 64,
            "action": "deny"
        }
    }
    """
    event: Dict[str, Any] = Field(
        description="Raw firewall log event as a flat key-value dict"
    )


# ---------------------------------------------------------------------------
# Response sub-models
# ---------------------------------------------------------------------------

class ThreatSignal(BaseModel):
    """
    One threat signal from ThreatSignalEmitter.
    Maps directly to the dict your threat_fusion.py already produces.
    """
    src_ip: str
    entity_type: str = "source_ip"
    threat_score: float = Field(description="Fused threat score 0-100")
    anomaly_score: float
    heuristic_score: float
    severity: str = Field(description="Low | Medium | High | Critical")
    cluster_label: str = Field(description="Normal | Suspicious | Isolated | Attack")
    attack_signals: int
    consensus_anomaly: bool
    evidence: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str

    # DB record ID — set after saving to firewall_alerts table
    alert_id: Optional[str] = None


class ValidationReport(BaseModel):
    """
    Log parsing validation summary from FirewallLogValidator.
    Flutter shows this as a banner at the top of the analysis results.
    """
    input_rows: int
    valid_rows: int
    dropped_rows: int
    duplicates_removed: int
    warnings: List[str] = Field(default_factory=list)


class AnomalyRow(BaseModel):
    """One row from the anomaly detection results DataFrame."""
    src_ip: str
    hour_window: str
    anomaly_score: float
    severity: str
    consensus_anomaly: bool
    failed_attempts: Optional[float] = None

    model_config = {"from_attributes": True}


class ClusterRow(BaseModel):
    """One row from the clustering results DataFrame."""
    src_ip: str
    total_events: int
    block_ratio: float
    unique_ports: int
    cluster_interpretation: str
    attack_signal_count: Optional[int] = None
    distance_outlier: Optional[bool] = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Response schemas — what the backend sends BACK to Flutter
# ---------------------------------------------------------------------------

class FirewallAnalyzeResponse(BaseModel):
    """
    Response for POST /api/v1/firewall/analyze (log file upload).
    Contains everything Flutter needs to populate the firewall module UI.
    """
    success: bool = True

    # Parsing summary shown as a banner in Flutter
    validation_report: ValidationReport

    # Threat signals — Flutter renders these as alert cards
    threat_signals: List[ThreatSignal] = Field(default_factory=list)

    # Anomaly table — Flutter renders as a sortable data table
    anomaly_results: List[AnomalyRow] = Field(default_factory=list)

    # Cluster table — Flutter renders as a grouped IP list
    cluster_results: List[ClusterRow] = Field(default_factory=list)

    # Summary counts for dashboard widgets
    total_ips_analyzed: int = 0
    suspicious_ips: int = 0
    malicious_ips: int = 0
    critical_ips: int = 0

    # Highest threat score seen in this analysis run
    max_threat_score: float = 0.0

    # Which log format was detected
    log_source: str = Field(
        default="unknown",
        description="windows | iptables | unknown"
    )


class FirewallIngestResponse(BaseModel):
    """
    Response for POST /api/v1/firewall/ingest (single real-time event).
    Flutter receives this after sending one live firewall log line.
    """
    success: bool = True

    # How many events are currently in the rolling buffer
    buffered_events: int

    # How many events were scored in the current time window
    scored_events: int

    # Any threat signals from the current window
    # Empty list means the current window looks normal
    threat_signals: List[ThreatSignal] = Field(default_factory=list)

    # True if any signal in this response is Suspicious or above
    alert_triggered: bool = False


class FirewallAlertOut(BaseModel):
    """
    One row from the firewall_alerts DB table.
    Used by GET /api/v1/firewall/alerts for the Flutter alerts list.
    """
    id: str
    timestamp: str
    src_ip: str
    threat_score: float
    anomaly_score: float
    heuristic_score: float
    severity: str
    cluster_label: str
    attack_signals: int
    consensus_anomaly: bool
    evidence_json: Optional[str] = None
    acknowledged: bool
    source_session: Optional[str] = None

    model_config = {"from_attributes": True}


class FirewallAlertsResponse(BaseModel):
    """Paginated list of stored firewall alerts."""
    success: bool = True
    total: int
    page: int
    page_size: int
    unacknowledged_count: int = 0
    alerts: List[FirewallAlertOut]


class AckResponse(BaseModel):
    """Response for PATCH /api/v1/firewall/alerts/{id}/acknowledge."""
    success: bool = True
    alert_id: str
    acknowledged: bool = True