"""
services/threat_scoring_service.py

Unified threat scoring for CyberSentinel — delegates to ThreatFusionService
while preserving backward-compatible UnifiedThreatScore responses.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.risk_levels import score_to_risk_level
from db.models import FirewallAlert, IPReputationCache, PacketEvent, ThreatScoreHistory
from schemas.threat_fusion import ThreatFusionInput
from schemas.threat_score import TopThreatsResponse, UnifiedThreatScore
from services.incident_service import IncidentService
from services.threat_fusion_service import ThreatFusionService
from services.threat_intel_service import ThreatIntelService


class ThreatScoringService:
    """Computes weighted ensemble threat scores for IP addresses."""

    def __init__(self, db: AsyncSession, user_id: str):
        self.db = db
        self.user_id = user_id
        self.intel = ThreatIntelService(db=db, user_id=user_id)
        self.fusion = ThreatFusionService(db=db, user_id=user_id)
        self.incidents = IncidentService(db=db, user_id=user_id)

    async def score(self, ip: str, src_context: dict) -> UnifiedThreatScore:
        """Compute full fusion score for one IP address."""
        inputs = await self._gather_inputs(ip, src_context)
        result = await self.fusion.fuse_and_persist(inputs)

        if self.fusion.should_auto_create_incident(result):
            await self.incidents.auto_create_from_threat(
                attack_type=result.attack_type or "Unknown",
                threat_score=result.threat_score,
                source_ip=ip,
                evidence=result.evidence,
                triggered_rules=src_context.get("triggered_rules", []),
            )

        return self._to_unified(result)

    async def _gather_inputs(self, ip: str, src_context: dict) -> ThreatFusionInput:
        packet_events = (
            await self.db.execute(
                select(PacketEvent)
                .where(PacketEvent.user_id == self.user_id, PacketEvent.src_ip == ip)
                .order_by(PacketEvent.timestamp.desc())
                .limit(50)
            )
        ).scalars().all()
        packet_scores = [float(e.threat_score_contribution or 0.0) for e in packet_events]
        packet_score = round(sum(packet_scores) / len(packet_scores), 2) if packet_scores else 0.0

        firewall_alerts = (
            await self.db.execute(
                select(FirewallAlert)
                .where(FirewallAlert.user_id == self.user_id, FirewallAlert.src_ip == ip)
                .order_by(FirewallAlert.timestamp.desc())
                .limit(10)
            )
        ).scalars().all()
        firewall_score = round(
            max((float(a.threat_score or 0.0) for a in firewall_alerts), default=0.0), 2
        )

        rule_score = float(src_context.get("rule_score", 0.0) or 0.0)
        if not rule_score and packet_events:
            rule_score = round(min(100.0, packet_score * 0.5), 2)

        intel_context = await self.intel.enrich(ip)
        ip_rep_score = round(float(intel_context.ip_reputation.threat_score or 0.0), 2)
        vt_score = round(float(intel_context.virustotal.threat_score or 0.0), 2)

        attack_type = src_context.get("attack_type")
        if not attack_type and packet_events:
            attack_type = packet_events[0].raw_model_prediction

        triggered_rules = list(src_context.get("triggered_rules") or [])

        return ThreatFusionInput(
            ip=ip,
            packet_score=packet_score,
            firewall_score=firewall_score,
            ip_reputation_score=ip_rep_score,
            virustotal_score=vt_score,
            rule_score=rule_score,
            attack_type=attack_type,
            triggered_rules=triggered_rules,
            context={
                **src_context,
                "packet_events_used": len(packet_events),
                "firewall_alerts_used": len(firewall_alerts),
                "intel": intel_context.model_dump(),
            },
        )

    async def top(self, limit: int = 20) -> TopThreatsResponse:
        """Return top IPs using stored telemetry + full fusion scoring."""
        uid = self.user_id
        rows = (
            await self.db.execute(
                select(
                    FirewallAlert.src_ip,
                    func.count().label("attempts"),
                    func.max(FirewallAlert.threat_score).label("max_score"),
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
                    )
                    .where(PacketEvent.user_id == uid, PacketEvent.src_ip.is_not(None))
                    .group_by(PacketEvent.src_ip)
                    .order_by(desc(func.max(PacketEvent.threat_score_contribution)))
                    .limit(limit)
                )
            ).all()

        scores: List[UnifiedThreatScore] = []
        for row in rows:
            if not row.src_ip:
                continue
            try:
                unified = await self.score(row.src_ip, {"source": "dashboard_top"})
                scores.append(unified)
            except Exception:
                max_score = round(float(row.max_score or 0.0), 2)
                scores.append(
                    UnifiedThreatScore(
                        ip=row.src_ip,
                        packet_score=max_score,
                        anomaly_score=max_score,
                        intel_score=0.0,
                        final_score=max_score,
                        threat_score=max_score,
                        risk_level=score_to_risk_level(max_score),
                        severity=score_to_risk_level(max_score),
                        classification="Unknown",
                        block_recommended=max_score >= 70.0,
                        reason="Fallback from stored telemetry",
                        evidence={"attempts": int(row.attempts), "source": "fallback"},
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    )
                )

        scores.sort(key=lambda s: s.final_score, reverse=True)
        return TopThreatsResponse(total=len(scores), results=scores)

    @staticmethod
    def _to_unified(result) -> UnifiedThreatScore:
        return UnifiedThreatScore(
            ip=result.ip,
            packet_score=result.packet_score,
            anomaly_score=result.firewall_score,
            intel_score=result.intel_score,
            final_score=result.threat_score,
            threat_score=result.threat_score,
            risk_level=result.risk_level,
            severity=result.risk_level,
            classification=result.classification,
            block_recommended=result.block_recommended,
            reason=result.reason,
            evidence=result.evidence,
            timestamp=result.timestamp,
            mitre_id=result.mitre.mitre_id if result.mitre else None,
            mitre_technique=result.mitre.technique if result.mitre else None,
            attack_type=result.attack_type,
        )
