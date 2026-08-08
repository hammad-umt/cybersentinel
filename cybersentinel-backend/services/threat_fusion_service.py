"""
Unified threat fusion scoring engine.

Combines packet ML, firewall anomaly, IP reputation, VirusTotal, and rule
confidence into a single 0–100 threat score with risk level classification.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.mitre_mapper import map_attack_to_mitre, mitre_from_rules, mitre_to_dict
from core.risk_levels import (
    INCIDENT_AUTO_CREATE_SCORE,
    is_critical_attack,
    score_to_risk_level,
)
from db.models import ThreatScoreHistory
from schemas.incident import MitreInfo
from schemas.threat_fusion import ThreatFusionInput, ThreatFusionResult


def compute_fusion_score(
    *,
    packet_score: float,
    firewall_score: float,
    ip_reputation_score: float,
    virustotal_score: float,
    rule_score: float,
) -> float:
    """Reusable weighted threat fusion formula."""
    raw = (
        packet_score * settings.FUSION_WEIGHT_PACKET
        + firewall_score * settings.FUSION_WEIGHT_FIREWALL
        + ip_reputation_score * settings.FUSION_WEIGHT_IP_REPUTATION
        + virustotal_score * settings.FUSION_WEIGHT_VIRUSTOTAL
        + rule_score * settings.FUSION_WEIGHT_RULES
    )
    return round(max(0.0, min(100.0, raw)), 2)


class ThreatFusionService:
    def __init__(self, db: AsyncSession, user_id: str):
        self.db = db
        self.user_id = user_id

    def fuse(self, data: ThreatFusionInput) -> ThreatFusionResult:
        threat_score = compute_fusion_score(
            packet_score=data.packet_score,
            firewall_score=data.firewall_score,
            ip_reputation_score=data.ip_reputation_score,
            virustotal_score=data.virustotal_score,
            rule_score=data.rule_score,
        )
        risk_level = score_to_risk_level(threat_score)

        attack_type = data.attack_type
        mitre_mapping = mitre_from_rules(data.triggered_rules) if data.triggered_rules else None
        if mitre_mapping is None and attack_type:
            mitre_mapping = map_attack_to_mitre(attack_type)
        mitre_info = MitreInfo(**mitre_to_dict(mitre_mapping)) if mitre_mapping else None

        classification = attack_type or "Unknown"
        block_recommended = threat_score >= 70.0 or risk_level in {"High", "Critical"}
        reason = self._build_reason(data, threat_score, risk_level)

        evidence = {
            **data.context,
            "weights": {
                "packet": settings.FUSION_WEIGHT_PACKET,
                "firewall": settings.FUSION_WEIGHT_FIREWALL,
                "ip_reputation": settings.FUSION_WEIGHT_IP_REPUTATION,
                "virustotal": settings.FUSION_WEIGHT_VIRUSTOTAL,
                "rules": settings.FUSION_WEIGHT_RULES,
            },
            "triggered_rules": data.triggered_rules,
        }
        if mitre_info:
            evidence["mitre"] = mitre_info.model_dump()

        timestamp = datetime.now(timezone.utc).isoformat()
        intel_combined = round(
            max(data.ip_reputation_score, 0.0) * 0.55
            + max(data.virustotal_score, 0.0) * 0.45,
            2,
        )

        return ThreatFusionResult(
            ip=data.ip,
            threat_score=threat_score,
            risk_level=risk_level,
            packet_score=round(data.packet_score, 2),
            firewall_score=round(data.firewall_score, 2),
            ip_reputation_score=round(data.ip_reputation_score, 2),
            virustotal_score=round(data.virustotal_score, 2),
            rule_score=round(data.rule_score, 2),
            attack_type=attack_type,
            mitre=mitre_info,
            classification=classification,
            block_recommended=block_recommended,
            reason=reason,
            evidence=evidence,
            timestamp=timestamp,
            final_score=threat_score,
            severity=risk_level,
            intel_score=intel_combined,
            anomaly_score=round(data.firewall_score, 2),
        )

    async def fuse_and_persist(self, data: ThreatFusionInput) -> ThreatFusionResult:
        result = self.fuse(data)
        await self._save_history(result)
        return result

    async def _save_history(self, result: ThreatFusionResult) -> None:
        row = ThreatScoreHistory(
            user_id=self.user_id,
            ip_address=result.ip,
            threat_score=result.threat_score,
            risk_level=result.risk_level,
            packet_score=result.packet_score,
            firewall_score=result.firewall_score,
            ip_reputation_score=result.ip_reputation_score,
            virustotal_score=result.virustotal_score,
            rule_score=result.rule_score,
            attack_type=result.attack_type,
            mitre_id=result.mitre.mitre_id if result.mitre else None,
            evidence_json=json.dumps(result.evidence, default=str),
        )
        self.db.add(row)
        await self.db.flush()

    def should_auto_create_incident(self, result: ThreatFusionResult) -> bool:
        return (
            result.threat_score >= INCIDENT_AUTO_CREATE_SCORE
            or is_critical_attack(result.attack_type, result.risk_level)
        )

    @staticmethod
    def _build_reason(data: ThreatFusionInput, score: float, risk_level: str) -> str:
        parts: list[str] = []
        if data.packet_score >= 50:
            parts.append(f"elevated packet ML score ({data.packet_score:.0f})")
        if data.firewall_score >= 50:
            parts.append(f"firewall anomaly ({data.firewall_score:.0f})")
        if data.ip_reputation_score >= 50:
            parts.append(f"IP reputation risk ({data.ip_reputation_score:.0f})")
        if data.virustotal_score >= 50:
            parts.append(f"VirusTotal detections ({data.virustotal_score:.0f})")
        if data.rule_score >= 30:
            parts.append(f"SOC rules ({data.rule_score:.0f})")
        if not parts:
            return f"Combined telemetry yields {risk_level} risk ({score:.0f}/100)."
        return f"Threat fusion: {', '.join(parts)} → {risk_level} ({score:.0f}/100)."
