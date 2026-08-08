"""Schemas for remote monitoring agents."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class AgentRegisterRequest(BaseModel):
  agent_id: str = Field(..., min_length=3, max_length=64)
  hostname: str = Field(..., min_length=1, max_length=128)
  metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentRegisterResponse(BaseModel):
  success: bool = True
  agent_id: str
  api_key: str = Field(description="Store securely — shown once at registration")
  message: str = "Agent registered successfully."


class AgentTelemetryRequest(BaseModel):
  agent_id: str
  hostname: Optional[str] = None
  packet_data: Dict[str, Any] = Field(default_factory=dict)
  firewall_logs: List[Dict[str, Any]] = Field(default_factory=list)


class AgentTelemetryResponse(BaseModel):
  success: bool = True
  agent_id: str
  packets_processed: int = 0
  firewall_events_processed: int = 0
  message: str = "Telemetry accepted."


class AgentStatusOut(BaseModel):
  agent_id: str
  hostname: str
  status: Literal["active", "inactive", "offline"]
  last_seen: Optional[str] = None
  registered_at: str


class AgentStatusResponse(BaseModel):
  success: bool = True
  agents: List[AgentStatusOut]
