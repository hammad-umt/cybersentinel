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


class DashboardSummary(BaseModel):
    success: bool = True
    packet_events: int = 0
    firewall_alerts: int = 0
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
