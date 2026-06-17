"""
SOC dashboard aggregation service.
"""

from __future__ import annotations

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import FirewallAlert, PacketEvent, ResponseAction
from schemas.dashboard import (
    DashboardSummary,
    ProtocolBucket,
    RecentAlert,
    SeverityBucket,
)


class DashboardService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def summary(self) -> DashboardSummary:
        packet_events = await self._count(PacketEvent)
        firewall_alerts = await self._count(FirewallAlert)
        response_actions = await self._count(ResponseAction)

        unacknowledged_alerts = (await self.db.execute(
            select(func.count()).select_from(FirewallAlert).where(FirewallAlert.acknowledged == False)  # noqa: E712
        )).scalar_one()
        critical_alerts = (await self.db.execute(
            select(func.count()).select_from(FirewallAlert).where(FirewallAlert.severity == "Critical")
        )).scalar_one()

        avg_packet = (await self.db.execute(
            select(func.avg(PacketEvent.threat_score_contribution))
        )).scalar_one()
        max_firewall = (await self.db.execute(
            select(func.max(FirewallAlert.threat_score))
        )).scalar_one()

        severity_rows = (await self.db.execute(
            select(FirewallAlert.severity, func.count())
            .group_by(FirewallAlert.severity)
            .order_by(desc(func.count()))
        )).all()
        protocol_rows = (await self.db.execute(
            select(PacketEvent.protocol, func.count())
            .where(PacketEvent.protocol.is_not(None))
            .group_by(PacketEvent.protocol)
            .order_by(desc(func.count()))
            .limit(10)
        )).all()
        recent_rows = (await self.db.execute(
            select(FirewallAlert)
            .order_by(FirewallAlert.timestamp.desc())
            .limit(10)
        )).scalars().all()

        return DashboardSummary(
            packet_events=packet_events,
            firewall_alerts=firewall_alerts,
            unacknowledged_alerts=unacknowledged_alerts,
            critical_alerts=critical_alerts,
            response_actions=response_actions,
            avg_packet_threat_score=round(float(avg_packet or 0.0), 2),
            max_firewall_threat_score=round(float(max_firewall or 0.0), 2),
            severity_distribution=[
                SeverityBucket(label=str(label), count=int(count))
                for label, count in severity_rows
            ],
            protocol_distribution=[
                ProtocolBucket(protocol=str(protocol), count=int(count))
                for protocol, count in protocol_rows
            ],
            recent_alerts=[
                RecentAlert(
                    id=row.id,
                    timestamp=row.timestamp,
                    src_ip=row.src_ip,
                    severity=row.severity,
                    threat_score=row.threat_score,
                    acknowledged=row.acknowledged,
                )
                for row in recent_rows
            ],
        )

    async def _count(self, model: type) -> int:
        return int((await self.db.execute(select(func.count()).select_from(model))).scalar_one())
