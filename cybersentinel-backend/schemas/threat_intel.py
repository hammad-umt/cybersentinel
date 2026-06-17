"""
schemas/threat_intel.py

Pydantic v2 response models for external threat intelligence enrichment.
These schemas normalize AbuseIPDB, GeoIP, and VirusTotal IP reputation data
so routers and scoring services do not expose raw provider payloads directly.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class IPIntelResult(BaseModel):
    """AbuseIPDB plus GeoIP reputation context for one IP address."""

    success: bool = True
    ip: str
    provider_status: Dict[str, str] = Field(default_factory=dict)
    abuse_confidence_score: Optional[int] = None
    total_reports: Optional[int] = None
    is_whitelisted: bool = False
    isp: Optional[str] = None
    usage_type: Optional[str] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    as_org: Optional[str] = None
    threat_score: float = 0.0
    cached: bool = False
    looked_up_at: str
    raw: Dict[str, Any] = Field(default_factory=dict)


class VTResult(BaseModel):
    """VirusTotal scan result summarized for CyberSentinel."""

    success: bool = True
    lookup_key: str
    scan_type: Literal["ip", "file", "url"] = "ip"
    ip: Optional[str] = None
    provider_status: str = "skipped"
    threat_level: str = "unknown"
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    total_engines: int = 0
    threat_score: float = 0.0
    cached: bool = False
    scanned_at: str
    raw: Dict[str, Any] = Field(default_factory=dict)


class URLScanRequest(BaseModel):
    """Request body for POST /api/v1/intel/url."""

    url: str = Field(min_length=1, max_length=256)


class EnrichedThreatContext(BaseModel):
    """Combined IP intelligence context used by unified threat scoring."""

    success: bool = True
    ip: str
    ip_reputation: IPIntelResult
    virustotal: VTResult
    intel_threat_score: float = Field(ge=0.0, le=100.0)
    provider_notes: List[str] = Field(default_factory=list)
    timestamp: str
