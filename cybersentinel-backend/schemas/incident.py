"""Pydantic schemas for security incident management."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


IncidentStatus = Literal["Open", "Investigating", "Resolved", "Closed"]


class IncidentCreateRequest(BaseModel):
  attack_type: str
  severity: str
  source_ip: Optional[str] = None
  destination_ip: Optional[str] = None
  threat_score: float = Field(ge=0.0, le=100.0)
  evidence: Dict[str, Any] = Field(default_factory=dict)
  title: Optional[str] = None
  notes: Optional[str] = None
  status: IncidentStatus = "Open"


class IncidentUpdateRequest(BaseModel):
  status: Optional[IncidentStatus] = None
  severity: Optional[str] = None
  notes: Optional[str] = None
  title: Optional[str] = None


class MitreInfo(BaseModel):
  attack_type: str
  mitre_id: str
  technique: str
  tactic: str


class IncidentOut(BaseModel):
  id: str
  timestamp: str
  attack_type: str
  severity: str
  source_ip: Optional[str] = None
  destination_ip: Optional[str] = None
  threat_score: float
  status: IncidentStatus
  mitre_id: Optional[str] = None
  mitre_technique: Optional[str] = None
  mitre_tactic: Optional[str] = None
  title: Optional[str] = None
  notes: Optional[str] = None
  evidence: Dict[str, Any] = Field(default_factory=dict)

  model_config = {"from_attributes": True}


class IncidentResponse(BaseModel):
  success: bool = True
  incident: IncidentOut


class IncidentsListResponse(BaseModel):
  success: bool = True
  total: int
  page: int
  page_size: int
  incidents: List[IncidentOut]
