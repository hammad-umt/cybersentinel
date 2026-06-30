"""
SOC dashboard aggregation service.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

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
        cutoff = (datetime.now(timezone.utc) - timedelta(days=settings.DASHBOARD_TREND_DAYS)).isoformat()
        day_bucket = iso_day_bucket(FirewallAlert.timestamp)
        db = self.db
        uid = self.user_id

        async def count_model(model: type) -> int:
            return int(
                (
                    await db.execute(
                        select(func.count())
                        .select_from(model)
                        .where(model.user_id == uid)
                    )
                ).scalar_one()
            )

        packet_events = await count_model(PacketEvent)
        firewall_alerts = await count_model(FirewallAlert)
        response_actions = await count_model(ResponseAction)
        unacknowledged_alerts = int(
            (
                await db.execute(
                    select(func.count())
                    .select_from(FirewallAlert)
                    .where(FirewallAlert.user_id == uid, FirewallAlert.acknowledged == False)  # noqa: E712
                )
            ).scalar_one()
        )
        critical_alerts = int(
            (
                await db.execute(
                    select(func.count())
                    .select_from(FirewallAlert)
                    .where(FirewallAlert.user_id == uid, FirewallAlert.severity == "Critical")
                )
            ).scalar_one()
        )
        avg_packet = (
            await db.execute(
                select(func.avg(PacketEvent.threat_score_contribution)).where(PacketEvent.user_id == uid)
            )
        ).scalar_one()
        max_firewall = (
            await db.execute(
                select(func.max(FirewallAlert.threat_score)).where(FirewallAlert.user_id == uid)
            )
        ).scalar_one()
        severity_rows = await db.execute(
            select(FirewallAlert.severity, func.count())
            .where(FirewallAlert.user_id == uid)
            .group_by(FirewallAlert.severity)
            .order_by(desc(func.count()))
        )
        protocol_rows = await db.execute(
            select(PacketEvent.protocol, func.count())
            .where(PacketEvent.user_id == uid, PacketEvent.protocol.is_not(None))
            .group_by(PacketEvent.protocol)
            .order_by(desc(func.count()))
            .limit(10)
        )
        recent_rows = await db.execute(
            select(FirewallAlert)
            .where(FirewallAlert.user_id == uid)
            .order_by(FirewallAlert.timestamp.desc())
            .limit(10)
        )
        trend_rows = await db.execute(
            select(day_bucket, func.count(), func.avg(FirewallAlert.threat_score))
            .where(FirewallAlert.user_id == uid, FirewallAlert.timestamp >= cutoff)
            .group_by(day_bucket)
            .order_by(day_bucket)
        )
        geo_rows = await db.execute(
            select(IPReputationCache.country_code, func.count())
            .where(
                IPReputationCache.user_id == uid,
                IPReputationCache.country_code.is_not(None),
            )
            .group_by(IPReputationCache.country_code)
            .order_by(desc(func.count()))
            .limit(20)
        )

        severity_counts: dict[str, int] = {}
        for label, count in severity_rows.all():
            public_label = translate_firewall_severity(str(label))
            severity_counts[public_label] = severity_counts.get(public_label, 0) + int(count)

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
                for protocol, count in protocol_rows.all()
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
                for row in recent_rows.scalars().all()
            ],
            geo_distribution=[
                GeoBucket(country_code=str(country), count=int(count))
                for country, count in geo_rows.all()
            ],
            trend=[
                TrendPoint(
                    day=str(day),
                    alert_count=int(count),
                    avg_threat_score=round(float(avg_score or 0.0), 2),
                )
                for day, count, avg_score in trend_rows.all()
            ],
        )
