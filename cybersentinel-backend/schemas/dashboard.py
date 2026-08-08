"""
Pydantic schemas for the SOC dashboard aggregation endpoints.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class SeverityBucket(BaseModel):
    label: str
    count: int = 0


class ProtocolBucket(BaseModel):
    protocol: str
    count: int = 0


class RecentAlert(BaseModel):
    id: str
    timestamp: str
    src_ip: str
    severity: str
    threat_score: float
    acknowledged: bool


class GeoBucket(BaseModel):
    country_code: str
    count: int = 0


class TrendPoint(BaseModel):
    day: str
    alert_count: int = 0
    avg_threat_score: float = 0.0
    incident_count: int = 0


class AttackBucket(BaseModel):
    attack_type: str
    count: int = 0


class MitreBucket(BaseModel):
    mitre_id: str
    technique: str
    count: int = 0


class IncidentStats(BaseModel):
    success: bool = True
    total: int = 0
    open: int = 0
    investigating: int = 0
    resolved: int = 0
    closed: int = 0
    critical: int = 0
    high: int = 0


class AttackDistribution(BaseModel):
    success: bool = True
    attacks: List[AttackBucket] = Field(default_factory=list)
    mitre: List[MitreBucket] = Field(default_factory=list)


class ThreatTrends(BaseModel):
    success: bool = True
    trend: List[TrendPoint] = Field(default_factory=list)
    top_attackers: List[Dict[str, object]] = Field(default_factory=list)


class DashboardSummary(BaseModel):
    success: bool = True
    packet_events: int = 0
    firewall_alerts: int = 0
    incidents: int = 0
    open_incidents: int = 0
    unacknowledged_alerts: int = 0
    critical_alerts: int = 0
    response_actions: int = 0
    avg_packet_threat_score: float = 0.0
    max_firewall_threat_score: float = 0.0
    severity_distribution: List[SeverityBucket] = Field(default_factory=list)
    protocol_distribution: List[ProtocolBucket] = Field(default_factory=list)
    recent_alerts: List[RecentAlert] = Field(default_factory=list)
    geo_distribution: Optional[List[GeoBucket]] = None
    trend: Optional[List[TrendPoint]] = None
