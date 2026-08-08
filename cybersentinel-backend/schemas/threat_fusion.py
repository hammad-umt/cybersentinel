"""Schemas for unified threat fusion scoring."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from schemas.incident import MitreInfo


class ThreatFusionInput(BaseModel):
  ip: str
  packet_score: float = Field(0.0, ge=0.0, le=100.0)
  firewall_score: float = Field(0.0, ge=0.0, le=100.0)
  ip_reputation_score: float = Field(0.0, ge=0.0, le=100.0)
  virustotal_score: float = Field(0.0, ge=0.0, le=100.0)
  rule_score: float = Field(0.0, ge=0.0, le=100.0)
  attack_type: Optional[str] = None
  triggered_rules: List[str] = Field(default_factory=list)
  context: Dict[str, Any] = Field(default_factory=dict)


class ThreatFusionResult(BaseModel):
  success: bool = True
  ip: str
  threat_score: float = Field(ge=0.0, le=100.0)
  risk_level: str = Field(description="Safe | Low | Medium | High | Critical")
  packet_score: float = Field(ge=0.0, le=100.0)
  firewall_score: float = Field(ge=0.0, le=100.0)
  ip_reputation_score: float = Field(ge=0.0, le=100.0)
  virustotal_score: float = Field(ge=0.0, le=100.0)
  rule_score: float = Field(ge=0.0, le=100.0)
  attack_type: Optional[str] = None
  mitre: Optional[MitreInfo] = None
  classification: str = "Unknown"
  block_recommended: bool = False
  reason: str = ""
  evidence: Dict[str, Any] = Field(default_factory=dict)
  timestamp: str

  # Backward-compatible aliases
  final_score: float = Field(ge=0.0, le=100.0)
  severity: str = Field(description="Alias of risk_level for legacy clients")
  intel_score: float = Field(0.0, ge=0.0, le=100.0)
  anomaly_score: float = Field(0.0, ge=0.0, le=100.0)


class ThreatFusionHistoryResponse(BaseModel):
  success: bool = True
  total: int
  results: List[ThreatFusionResult]
