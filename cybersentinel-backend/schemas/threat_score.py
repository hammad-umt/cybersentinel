"""
schemas/threat_score.py

Pydantic v2 schemas for CyberSentinel's unified threat scoring endpoint.
The unified score combines packet ML evidence, firewall anomaly evidence, and
external threat intelligence into one severity label for the frontend.
"""

from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class UnifiedThreatScore(BaseModel):
    """Weighted ensemble score for a single IP address."""

    success: bool = True
    ip: str
    packet_score: float = Field(ge=0.0, le=100.0)
    anomaly_score: float = Field(ge=0.0, le=100.0)
    intel_score: float = Field(ge=0.0, le=100.0)
    final_score: float = Field(ge=0.0, le=100.0)
    severity: str = Field(description="Low | Medium | High | Critical")
    evidence: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str


class TopThreatsResponse(BaseModel):
    """Top scored IPs returned by GET /api/v1/threat/top."""

    success: bool = True
    total: int
    results: List[UnifiedThreatScore]
