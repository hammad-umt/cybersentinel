"""
services/threat_scoring_service.py

Unified threat scoring for CyberSentinel.
This service combines supervised packet classifier evidence, unsupervised
firewall anomaly alerts, and threat intelligence into one weighted score.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.severity import score_to_public_severity
from db.models import FirewallAlert, PacketEvent
from schemas.threat_score import TopThreatsResponse, UnifiedThreatScore
from services.threat_intel_service import ThreatIntelService


class ThreatScoringService:
    """Computes weighted ensemble threat scores for IP addresses."""

    def __init__(self, db: AsyncSession, user_id: str):
        self.db = db
        self.user_id = user_id
        self.intel = ThreatIntelService(db=db, user_id=user_id)

    async def score(self, ip: str, src_context: dict) -> UnifiedThreatScore:
        """Compute packet, anomaly, and intel scores for one IP address."""
        packet_events = (await self.db.execute(
            select(PacketEvent)
            .where(PacketEvent.user_id == self.user_id, PacketEvent.src_ip == ip)
            .order_by(PacketEvent.timestamp.desc())
            .limit(50)
        )).scalars().all()
        packet_scores = [float(event.threat_score_contribution or 0.0) for event in packet_events]
        packet_score = round(sum(packet_scores) / len(packet_scores), 2) if packet_scores else 0.0

        firewall_alerts = (await self.db.execute(
            select(FirewallAlert)
            .where(FirewallAlert.user_id == self.user_id, FirewallAlert.src_ip == ip)
            .order_by(FirewallAlert.timestamp.desc())
            .limit(10)
        )).scalars().all()
        anomaly_score = round(max((float(alert.threat_score or 0.0) for alert in firewall_alerts), default=0.0), 2)

        intel_context = await self.intel.enrich(ip)
        intel_score = round(intel_context.intel_threat_score, 2)

        intel_weight = settings.ENSEMBLE_WEIGHT_VIRUSTOTAL + settings.ENSEMBLE_WEIGHT_IP_REPUTATION
        final_score = round(min(100.0, max(0.0, (
            packet_score * settings.ENSEMBLE_WEIGHT_PACKET
            + anomaly_score * settings.ENSEMBLE_WEIGHT_ANOMALY
            + intel_score * intel_weight
        ))), 2)

        classification = "Unknown"
        block_recommended = False
        reason = "No high-risk external intelligence signal detected."
        if intel_score >= 70.0:
            classification = "Known Malicious IP"
            block_recommended = True
            reason = "High reputation risk from external intelligence providers"

        evidence = {
            "source_context": src_context,
            "packet_events_used": len(packet_events),
            "firewall_alerts_used": len(firewall_alerts),
            "recent_packet_event_ids": [event.id for event in packet_events[:10]],
            "recent_firewall_alert_ids": [alert.id for alert in firewall_alerts[:10]],
            "intel": intel_context.model_dump(),
            "weights": {
                "packet": settings.ENSEMBLE_WEIGHT_PACKET,
                "anomaly": settings.ENSEMBLE_WEIGHT_ANOMALY,
                "intel": intel_weight,
            },
        }

        return UnifiedThreatScore(
            ip=ip,
            packet_score=packet_score,
            anomaly_score=anomaly_score,
            intel_score=intel_score,
            final_score=final_score,
            severity=score_to_public_severity(final_score),
            classification=classification,
            block_recommended=block_recommended,
            reason=reason,
            evidence=evidence,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    async def top(self, limit: int = 20) -> TopThreatsResponse:
        """Return top IPs discovered in packet events and firewall alerts."""
        packet_ips = (await self.db.execute(
            select(PacketEvent.src_ip)
            .where(PacketEvent.user_id == self.user_id, PacketEvent.src_ip.is_not(None))
            .distinct()
        )).scalars().all()
        firewall_ips = (await self.db.execute(
            select(FirewallAlert.src_ip)
            .where(FirewallAlert.user_id == self.user_id, FirewallAlert.src_ip.is_not(None))
            .distinct()
        )).scalars().all()

        candidates = sorted({ip for ip in [*packet_ips, *firewall_ips] if ip})
        scores: List[UnifiedThreatScore] = []
        for ip in candidates:
            scores.append(await self.score(ip, {"source": "top"}))

        scores.sort(key=lambda item: item.final_score, reverse=True)
        return TopThreatsResponse(
            total=len(scores[:limit]),
            results=scores[:limit],
        )

