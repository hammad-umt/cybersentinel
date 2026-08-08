"""
schemas/threat_score.py

Pydantic v2 schemas for CyberSentinel's unified threat scoring endpoint.
The unified score combines packet ML evidence, firewall anomaly evidence, and
external threat intelligence into one severity label for the frontend.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class UnifiedThreatScore(BaseModel):
    """Weighted ensemble score for a single IP address."""

    success: bool = True
    ip: str
    packet_score: float = Field(ge=0.0, le=100.0)
    anomaly_score: float = Field(ge=0.0, le=100.0, description="Firewall anomaly score")
    intel_score: float = Field(ge=0.0, le=100.0)
    final_score: float = Field(ge=0.0, le=100.0, description="Legacy alias of threat_score")
    threat_score: float = Field(ge=0.0, le=100.0)
    risk_level: str = Field(description="Safe | Low | Medium | High | Critical")
    severity: str = Field(description="Legacy alias of risk_level")
    attack_type: Optional[str] = None
    mitre_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    classification: str = Field(description="Primary classification label for the IP")
    block_recommended: bool = Field(description="Whether the IP should be blocked")
    reason: str = Field(description="Decision rationale for the classification")
    evidence: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str


class TopThreatsResponse(BaseModel):
    """Top scored IPs returned by GET /api/v1/threat/top."""

    success: bool = True
    total: int
    results: List[UnifiedThreatScore]
