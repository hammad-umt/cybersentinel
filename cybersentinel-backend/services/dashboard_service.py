"""
SOC dashboard aggregation service.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.severity import translate_firewall_severity
from db.models import FirewallAlert, IPReputationCache, PacketEvent, ResponseAction
from db.sql_compat import iso_day_bucket
from schemas.dashboard import (
    DashboardSummary,
    GeoBucket,
    ProtocolBucket,
    RecentAlert,
    SeverityBucket,
    TrendPoint,
)


class DashboardService:
    def __init__(self, db: AsyncSession, user_id: str):
        self.db = db
        self.user_id = user_id

    async def summary(self) -> DashboardSummary:
        packet_events = await self._count(PacketEvent)
        firewall_alerts = await self._count(FirewallAlert)
        response_actions = await self._count(ResponseAction)

        unacknowledged_alerts = (await self.db.execute(
            select(func.count())
            .select_from(FirewallAlert)
            .where(
                FirewallAlert.user_id == self.user_id,
                FirewallAlert.acknowledged == False,  # noqa: E712
            )
        )).scalar_one()
        critical_alerts = (await self.db.execute(
            select(func.count())
            .select_from(FirewallAlert)
            .where(
                FirewallAlert.user_id == self.user_id,
                FirewallAlert.severity == "Critical",
            )
        )).scalar_one()

        avg_packet = (await self.db.execute(
            select(func.avg(PacketEvent.threat_score_contribution))
            .where(PacketEvent.user_id == self.user_id)
        )).scalar_one()
        max_firewall = (await self.db.execute(
            select(func.max(FirewallAlert.threat_score))
            .where(FirewallAlert.user_id == self.user_id)
        )).scalar_one()

        severity_rows = (await self.db.execute(
            select(FirewallAlert.severity, func.count())
            .where(FirewallAlert.user_id == self.user_id)
            .group_by(FirewallAlert.severity)
            .order_by(desc(func.count()))
        )).all()
        severity_counts: dict[str, int] = {}
        for label, count in severity_rows:
            public_label = translate_firewall_severity(str(label))
            severity_counts[public_label] = severity_counts.get(public_label, 0) + int(count)
        protocol_rows = (await self.db.execute(
            select(PacketEvent.protocol, func.count())
            .where(PacketEvent.user_id == self.user_id, PacketEvent.protocol.is_not(None))
            .group_by(PacketEvent.protocol)
            .order_by(desc(func.count()))
            .limit(10)
        )).all()
        recent_rows = (await self.db.execute(
            select(FirewallAlert)
            .where(FirewallAlert.user_id == self.user_id)
            .order_by(FirewallAlert.timestamp.desc())
            .limit(10)
        )).scalars().all()

        cutoff = (datetime.now(timezone.utc) - timedelta(days=settings.DASHBOARD_TREND_DAYS)).isoformat()
        day_bucket = iso_day_bucket(FirewallAlert.timestamp)
        trend_rows = (await self.db.execute(
            select(
                day_bucket,
                func.count(),
                func.avg(FirewallAlert.threat_score),
            )
            .where(
                FirewallAlert.user_id == self.user_id,
                FirewallAlert.timestamp >= cutoff,
            )
            .group_by(day_bucket)
            .order_by(day_bucket)
        )).all()
        geo_rows = (await self.db.execute(
            select(IPReputationCache.country_code, func.count())
            .join(
                FirewallAlert,
                (FirewallAlert.src_ip == IPReputationCache.ip_address)
                & (FirewallAlert.user_id == IPReputationCache.user_id),
            )
            .where(
                IPReputationCache.user_id == self.user_id,
                IPReputationCache.country_code.is_not(None),
            )
            .group_by(IPReputationCache.country_code)
            .order_by(desc(func.count()))
            .limit(20)
        )).all()

        return DashboardSummary(
            packet_events=packet_events,
            firewall_alerts=firewall_alerts,
            unacknowledged_alerts=unacknowledged_alerts,
            critical_alerts=critical_alerts,
            response_actions=response_actions,
            avg_packet_threat_score=round(float(avg_packet or 0.0), 2),
            max_firewall_threat_score=round(float(max_firewall or 0.0), 2),
            severity_distribution=[
                SeverityBucket(label=label, count=count)
                for label, count in sorted(
                    severity_counts.items(),
                    key=lambda item: item[1],
                    reverse=True,
                )
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
                    severity=translate_firewall_severity(row.severity),
                    threat_score=row.threat_score,
                    acknowledged=row.acknowledged,
                )
                for row in recent_rows
            ],
            geo_distribution=[
                GeoBucket(country_code=str(country), count=int(count))
                for country, count in geo_rows
            ],
            trend=[
                TrendPoint(
                    day=str(day),
                    alert_count=int(count),
                    avg_threat_score=round(float(avg_score or 0.0), 2),
                )
                for day, count, avg_score in trend_rows
            ],
        )

    async def _count(self, model: type) -> int:
        return int(
            (
                await self.db.execute(
                    select(func.count())
                    .select_from(model)
                    .where(model.user_id == self.user_id)
                )
            ).scalar_one()
        )
