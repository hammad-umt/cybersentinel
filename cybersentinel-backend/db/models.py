"""
db/models.py

SQLAlchemy ORM table definitions for CyberSentinel.

Tables:
  - packet_events     → every classified packet/flow result
  - firewall_alerts   → threat signals from the unsupervised firewall pipeline
  - virus_scan_cache  → cached VirusTotal results (avoid re-hitting API)
  - ip_reputation_cache → cached AbuseIPDB + GeoIP results
  - response_actions  → audit log for threat response actions

Design decisions:
  - All primary keys are UUIDs (String) for distributed-safe IDs.
  - All timestamps are stored as UTC ISO strings for simplicity with SQLite.
  - JSON columns store the raw evidence dicts from your ML models.
  - Indexes on the columns Flutter will filter/sort by most often.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Float,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from db.database import Base


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _now_utc() -> str:
    """Returns current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _new_uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Table 1 — Packet Events
# Stores every result from the supervised packet classifier.
# ---------------------------------------------------------------------------

class PacketEvent(Base):
    __tablename__ = "packet_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )

    # When the packet was classified
    timestamp: Mapped[str] = mapped_column(
        String(32), default=_now_utc, index=True, nullable=False
    )

    # Source and destination (extracted from the flow)
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)   # IPv4 or IPv6
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(10))

    # ML output
    prediction: Mapped[str] = mapped_column(
        String(32), index=True, nullable=False
    )  # Normal | Suspicious | Malicious | Insufficient Evidence

    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    prob_normal: Mapped[float | None] = mapped_column(Float)
    prob_suspicious: Mapped[float | None] = mapped_column(Float)
    prob_malicious: Mapped[float | None] = mapped_column(Float)

    # Feature coverage info from the classifier
    feature_coverage: Mapped[float | None] = mapped_column(Float)
    missing_feature_count: Mapped[int | None] = mapped_column(Integer)
    traffic_schema: Mapped[str | None] = mapped_column(String(64))

    # Threat score contribution (0-100) fed into ensemble later
    threat_score_contribution: Mapped[float] = mapped_column(Float, default=0.0)

    # Was this result from a batch CSV upload or a single live flow?
    source: Mapped[str] = mapped_column(
        String(20), default="single"
    )  # single | batch | realtime

    __table_args__ = (
        Index("ix_packet_events_prediction_timestamp", "prediction", "timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<PacketEvent id={self.id!r} src={self.src_ip!r} "
            f"prediction={self.prediction!r} confidence={self.confidence:.2f}>"
        )


# ---------------------------------------------------------------------------
# Table 2 — Firewall Alerts
# Stores threat signals emitted by ThreatSignalEmitter (threat_fusion.py).
# One row per source IP per detection window.
# ---------------------------------------------------------------------------

class FirewallAlert(Base):
    __tablename__ = "firewall_alerts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )

    timestamp: Mapped[str] = mapped_column(
        String(32), default=_now_utc, index=True, nullable=False
    )

    # The IP that triggered the alert
    src_ip: Mapped[str] = mapped_column(
        String(45), index=True, nullable=False
    )

    # Fused scores from ThreatSignalEmitter
    threat_score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    heuristic_score: Mapped[float] = mapped_column(Float, nullable=False)

    # Severity label: Normal | Suspicious | Malicious-like | Critical
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )

    # Cluster interpretation: Normal | Suspicious | Isolated | Attack
    cluster_label: Mapped[str] = mapped_column(String(20), nullable=False)

    # How many attack signals fired (port scan, brute force, off-hours, etc.)
    attack_signals: Mapped[int] = mapped_column(Integer, default=0)

    # Did both Isolation Forest AND heuristics agree it's anomalous?
    consensus_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)

    # Raw evidence dict from ThreatSignalEmitter stored as JSON string
    # e.g. {"unique_ports": 12, "block_ratio": 0.9, "total_events": 45}
    evidence_json: Mapped[str | None] = mapped_column(Text)

    # Has this alert been acknowledged by an admin in the Flutter UI?
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    # Which log file or input session produced this alert
    source_session: Mapped[str | None] = mapped_column(String(128))

    __table_args__ = (
        Index("ix_firewall_alerts_severity_timestamp", "severity", "timestamp"),
        Index("ix_firewall_alerts_src_ip_timestamp", "src_ip", "timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<FirewallAlert id={self.id!r} src_ip={self.src_ip!r} "
            f"severity={self.severity!r} threat_score={self.threat_score:.1f}>"
        )


# ---------------------------------------------------------------------------
# Table 3 — Virus Scan Cache
# Caches VirusTotal results so the same file/URL isn't scanned twice.
# TTL is enforced in VirusService, not at DB level.
# ---------------------------------------------------------------------------

class VirusScanCache(Base):
    __tablename__ = "virus_scan_cache"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )

    # SHA-256 hash for files, raw URL for URL scans
    lookup_key: Mapped[str] = mapped_column(
        String(256), unique=True, index=True, nullable=False
    )

    scan_type: Mapped[str] = mapped_column(String(10), nullable=False)  # file | url

    # When VT returned this result
    scanned_at: Mapped[str] = mapped_column(
        String(32), default=_now_utc, nullable=False
    )

    # Overall threat verdict
    threat_level: Mapped[str] = mapped_column(String(20), nullable=False)  # clean | suspicious | malicious
    malicious_count: Mapped[int] = mapped_column(Integer, default=0)
    suspicious_count: Mapped[int] = mapped_column(Integer, default=0)
    total_engines: Mapped[int] = mapped_column(Integer, default=0)

    # Threat score contribution (0-100) derived from detection ratio
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Full VT response stored as JSON string for the Flutter detail view
    raw_result_json: Mapped[str | None] = mapped_column(Text)

    def __repr__(self) -> str:
        return (
            f"<VirusScanCache key={self.lookup_key!r} "
            f"threat={self.threat_level!r} engines={self.malicious_count}/{self.total_engines}>"
        )


# ---------------------------------------------------------------------------
# Table 4 — IP Reputation Cache
# Caches AbuseIPDB + GeoIP results per IP address.
# ---------------------------------------------------------------------------

class IPReputationCache(Base):
    __tablename__ = "ip_reputation_cache"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )

    ip_address: Mapped[str] = mapped_column(
        String(45), unique=True, index=True, nullable=False
    )

    looked_up_at: Mapped[str] = mapped_column(
        String(32), default=_now_utc, nullable=False
    )

    # AbuseIPDB fields
    abuse_confidence_score: Mapped[int | None] = mapped_column(Integer)   # 0-100
    total_reports: Mapped[int | None] = mapped_column(Integer)
    is_whitelisted: Mapped[bool] = mapped_column(Boolean, default=False)
    isp: Mapped[str | None] = mapped_column(String(128))
    usage_type: Mapped[str | None] = mapped_column(String(64))            # e.g. "Data Center/Web Hosting/Transit"

    # GeoIP fields
    country_code: Mapped[str | None] = mapped_column(String(4))
    country_name: Mapped[str | None] = mapped_column(String(64))
    city: Mapped[str | None] = mapped_column(String(64))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    asn: Mapped[str | None] = mapped_column(String(16))
    as_org: Mapped[str | None] = mapped_column(String(256))

    # Derived threat score (0-100) fed into ensemble
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Full response JSON for the Flutter IP detail view
    raw_result_json: Mapped[str | None] = mapped_column(Text)

    def __repr__(self) -> str:
        return (
            f"<IPReputationCache ip={self.ip_address!r} "
            f"abuse_score={self.abuse_confidence_score} country={self.country_code!r}>"
        )


# ---------------------------------------------------------------------------
# Table 5 — Response Actions
# Stores admin response actions such as block, whitelist, watchlist, and
# firewall-rule removal. Execution is controlled by the response service so
# the audit trail exists even when the platform runs in dry-run/demo mode.
# ---------------------------------------------------------------------------

class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )

    timestamp: Mapped[str] = mapped_column(
        String(32), default=_now_utc, index=True, nullable=False
    )

    target_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    action: Mapped[str] = mapped_column(
        String(32), index=True, nullable=False
    )  # block_ip | remove_firewall_rule | whitelist | watchlist | unblock_ip

    status: Mapped[str] = mapped_column(
        String(20), index=True, nullable=False
    )  # recorded | executed | failed | dry_run

    requested_by: Mapped[str | None] = mapped_column(String(128))
    reason: Mapped[str | None] = mapped_column(Text)
    command_preview: Mapped[str | None] = mapped_column(Text)
    result_message: Mapped[str | None] = mapped_column(Text)
    executed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    __table_args__ = (
        Index("ix_response_actions_target_timestamp", "target_ip", "timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<ResponseAction id={self.id!r} target_ip={self.target_ip!r} "
            f"action={self.action!r} status={self.status!r}>"
        )


# ---------------------------------------------------------------------------
# Table 6 — Users (JWT authentication — Sprint 3)
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(32), nullable=False, default="Analyst"
    )  # Administrator | Analyst | SeniorManagement
    password_reset_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    password_reset_expires: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), default=_now_utc, nullable=False)

    def __repr__(self) -> str:
        return f"<User id={self.id!r} email={self.email!r} role={self.role!r}>"


# ---------------------------------------------------------------------------
# Table 7 — Per-user configuration (encrypted API keys, preferences)
# ---------------------------------------------------------------------------

class UserConfiguration(Base):
    __tablename__ = "user_configurations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    user_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    encrypted_vt_key: Mapped[str | None] = mapped_column(Text)
    encrypted_abuse_key: Mapped[str | None] = mapped_column(Text)
    theme_preference: Mapped[str] = mapped_column(String(8), default="Dark")
    background_monitoring: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[str] = mapped_column(String(32), default=_now_utc, nullable=False)

