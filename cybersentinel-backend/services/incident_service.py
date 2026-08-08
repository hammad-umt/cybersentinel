"""Security incident lifecycle management."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.mitre_mapper import map_attack_to_mitre, mitre_to_dict
from core.risk_levels import score_to_risk_level
from db.models import Incident
from schemas.incident import (
    IncidentCreateRequest,
    IncidentOut,
    IncidentResponse,
    IncidentsListResponse,
    IncidentUpdateRequest,
)
from services.alert_broadcast import alert_hub


def _loads(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def _incident_to_out(row: Incident) -> IncidentOut:
    return IncidentOut(
        id=row.id,
        timestamp=row.timestamp,
        attack_type=row.attack_type,
        severity=row.severity,
        source_ip=row.source_ip,
        destination_ip=row.destination_ip,
        threat_score=row.threat_score,
        status=row.status,  # type: ignore[arg-type]
        mitre_id=row.mitre_id,
        mitre_technique=row.mitre_technique,
        mitre_tactic=row.mitre_tactic,
        title=row.title,
        notes=row.notes,
        evidence=_loads(row.evidence_json),
    )


class IncidentService:
    def __init__(self, db: AsyncSession, user_id: str):
        self.db = db
        self.user_id = user_id

    async def create(self, body: IncidentCreateRequest) -> IncidentResponse:
        mitre = map_attack_to_mitre(body.attack_type)
        row = Incident(
            user_id=self.user_id,
            attack_type=body.attack_type,
            severity=body.severity or score_to_risk_level(body.threat_score),
            source_ip=body.source_ip,
            destination_ip=body.destination_ip,
            threat_score=body.threat_score,
            status=body.status,
            mitre_id=mitre.mitre_id,
            mitre_technique=mitre.technique,
            mitre_tactic=mitre.tactic,
            evidence_json=json.dumps(body.evidence, default=str),
            title=body.title or f"{body.attack_type} — {body.source_ip or 'unknown'}",
            notes=body.notes,
        )
        self.db.add(row)
        await self.db.flush()
        await self.db.refresh(row)

        incident = _incident_to_out(row)
        await alert_hub.publish_incident(
            self.user_id,
            {"action": "created", "incident": incident.model_dump()},
        )
        return IncidentResponse(incident=incident)

    async def auto_create_from_threat(
        self,
        *,
        attack_type: str,
        threat_score: float,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        evidence: dict[str, Any] | None = None,
        triggered_rules: list[str] | None = None,
    ) -> IncidentResponse | None:
        """Create incident when score exceeds threshold or critical attack detected."""
        risk = score_to_risk_level(threat_score)
        from core.risk_levels import is_critical_attack

        if threat_score < settings.INCIDENT_AUTO_CREATE_THRESHOLD and not is_critical_attack(
            attack_type, risk
        ):
            return None

        # Dedupe: skip if open incident exists for same IP + attack type in last hour
        if source_ip:
            recent = await self.db.execute(
                select(Incident)
                .where(
                    Incident.user_id == self.user_id,
                    Incident.source_ip == source_ip,
                    Incident.attack_type == attack_type,
                    Incident.status.in_(("Open", "Investigating")),
                )
                .order_by(desc(Incident.timestamp))
                .limit(1)
            )
            if recent.scalar_one_or_none():
                return None

        body = IncidentCreateRequest(
            attack_type=attack_type,
            severity=risk,
            source_ip=source_ip,
            destination_ip=destination_ip,
            threat_score=threat_score,
            evidence={
                **(evidence or {}),
                "triggered_rules": triggered_rules or [],
                "auto_created": True,
            },
            status="Open",
        )
        return await self.create(body)

    async def list_incidents(
        self,
        page: int = 1,
        page_size: int = 50,
        status_filter: str | None = None,
    ) -> IncidentsListResponse:
        page_size = min(page_size, settings.MAX_PAGE_SIZE)
        offset = (page - 1) * page_size
        query = select(Incident).where(Incident.user_id == self.user_id)
        count_q = select(func.count()).select_from(Incident).where(Incident.user_id == self.user_id)
        if status_filter:
            query = query.where(Incident.status == status_filter)
            count_q = count_q.where(Incident.status == status_filter)
        total = (await self.db.execute(count_q)).scalar_one()
        rows = (
            await self.db.execute(
                query.order_by(desc(Incident.timestamp)).offset(offset).limit(page_size)
            )
        ).scalars().all()
        return IncidentsListResponse(
            total=int(total),
            page=page,
            page_size=page_size,
            incidents=[_incident_to_out(r) for r in rows],
        )

    async def get(self, incident_id: str) -> IncidentOut | None:
        row = (
            await self.db.execute(
                select(Incident).where(
                    Incident.user_id == self.user_id,
                    Incident.id == incident_id,
                )
            )
        ).scalar_one_or_none()
        return _incident_to_out(row) if row else None

    async def update(self, incident_id: str, body: IncidentUpdateRequest) -> IncidentResponse | None:
        row = (
            await self.db.execute(
                select(Incident).where(
                    Incident.user_id == self.user_id,
                    Incident.id == incident_id,
                )
            )
        ).scalar_one_or_none()
        if not row:
            return None
        if body.status is not None:
            row.status = body.status
        if body.severity is not None:
            row.severity = body.severity
        if body.notes is not None:
            row.notes = body.notes
        if body.title is not None:
            row.title = body.title
        await self.db.flush()
        await self.db.refresh(row)
        incident = _incident_to_out(row)
        await alert_hub.publish_incident(
            self.user_id,
            {"action": "updated", "incident": incident.model_dump()},
        )
        return IncidentResponse(incident=incident)
