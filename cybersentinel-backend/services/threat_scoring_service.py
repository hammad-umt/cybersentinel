"""
services/threat_scoring_service.py

Unified threat scoring for CyberSentinel.
This service combines supervised packet classifier evidence, unsupervised
firewall anomaly alerts, and threat intelligence into one weighted score.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.severity import score_to_public_severity
from db.models import FirewallAlert, IPReputationCache, PacketEvent
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
        """
        Return top malicious IPs for the dashboard.

        Uses aggregated Supabase/PostgreSQL telemetry only — no per-IP external
        API calls (the old implementation scored every distinct IP via VirusTotal).
        """
        uid = self.user_id
        rows = (
            await self.db.execute(
                select(
                    FirewallAlert.src_ip,
                    func.count().label("attempts"),
                    func.max(FirewallAlert.threat_score).label("max_score"),
                    func.avg(PacketEvent.threat_score_contribution).label("packet_avg"),
                )
                .outerjoin(
                    PacketEvent,
                    (PacketEvent.src_ip == FirewallAlert.src_ip)
                    & (PacketEvent.user_id == FirewallAlert.user_id),
                )
                .where(FirewallAlert.user_id == uid, FirewallAlert.src_ip.is_not(None))
                .group_by(FirewallAlert.src_ip)
                .order_by(desc(func.max(FirewallAlert.threat_score)))
                .limit(limit)
            )
        ).all()

        if not rows:
            rows = (
                await self.db.execute(
                    select(
                        PacketEvent.src_ip,
                        func.count().label("attempts"),
                        func.max(PacketEvent.threat_score_contribution).label("max_score"),
                        func.avg(PacketEvent.threat_score_contribution).label("packet_avg"),
                    )
                    .where(PacketEvent.user_id == uid, PacketEvent.src_ip.is_not(None))
                    .group_by(PacketEvent.src_ip)
                    .order_by(desc(func.max(PacketEvent.threat_score_contribution)))
                    .limit(limit)
                )
            ).all()

        ips = [row.src_ip for row in rows if row.src_ip]
        country_map: dict[str, str] = {}
        if ips:
            cache_rows = (
                await self.db.execute(
                    select(IPReputationCache.ip_address, IPReputationCache.country_code)
                    .where(
                        IPReputationCache.user_id == uid,
                        IPReputationCache.ip_address.in_(ips),
                        IPReputationCache.country_code.is_not(None),
                    )
                )
            ).all()
            country_map = {ip: str(country) for ip, country in cache_rows}

        scores: List[UnifiedThreatScore] = []
        for row in rows:
            if not row.src_ip:
                continue
            max_score = round(float(row.max_score or 0.0), 2)
            packet_avg = round(float(row.packet_avg or 0.0), 2)
            country = country_map.get(row.src_ip)
            scores.append(
                UnifiedThreatScore(
                    ip=row.src_ip,
                    packet_score=packet_avg,
                    anomaly_score=max_score,
                    intel_score=0.0,
                    final_score=max_score,
                    severity=score_to_public_severity(max_score),
                    classification=country or "Unknown",
                    block_recommended=max_score >= 70.0,
                    reason="Aggregated from stored firewall and packet telemetry",
                    evidence={
                        "attempts": int(row.attempts),
                        "country": country,
                        "source": "dashboard_fast_path",
                    },
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
            )

        return TopThreatsResponse(total=len(scores), results=scores)

