"""
SOC dashboard aggregation service — parallel Supabase queries.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.severity import translate_firewall_severity
from db.database import AsyncSessionLocal
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

T = TypeVar("T")


async def _run_parallel(user_id: str, *tasks: Callable[[AsyncSession, str], Awaitable[Any]]) -> tuple:
    """Run read queries on independent Supabase sessions in parallel."""

    async def _one(task: Callable[[AsyncSession, str], Awaitable[Any]]) -> Any:
        async with AsyncSessionLocal() as session:
            return await task(session, user_id)

    return await asyncio.gather(*[_one(task) for task in tasks])


class DashboardService:
    def __init__(self, db: AsyncSession, user_id: str):
        self.db = db
        self.user_id = user_id

    async def summary(self) -> DashboardSummary:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=settings.DASHBOARD_TREND_DAYS)).isoformat()
        day_bucket = iso_day_bucket(FirewallAlert.timestamp)

        async def count_model(session: AsyncSession, uid: str, model: type) -> int:
            return int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(model)
                        .where(model.user_id == uid)
                    )
                ).scalar_one()
            )

        async def scalar_count(session: AsyncSession, uid: str, stmt) -> int:
            return int((await session.execute(stmt)).scalar_one())

        async def scalar(session: AsyncSession, uid: str, stmt):
            return (await session.execute(stmt)).scalar_one()

        (
            packet_events,
            firewall_alerts,
            response_actions,
            unacknowledged_alerts,
            critical_alerts,
            avg_packet,
            max_firewall,
            severity_rows,
            protocol_rows,
            recent_rows,
            trend_rows,
            geo_rows,
        ) = await _run_parallel(
            self.user_id,
            lambda s, u: count_model(s, u, PacketEvent),
            lambda s, u: count_model(s, u, FirewallAlert),
            lambda s, u: count_model(s, u, ResponseAction),
            lambda s, u: scalar_count(
                s,
                u,
                select(func.count())
                .select_from(FirewallAlert)
                .where(FirewallAlert.user_id == u, FirewallAlert.acknowledged == False),  # noqa: E712
            ),
            lambda s, u: scalar_count(
                s,
                u,
                select(func.count())
                .select_from(FirewallAlert)
                .where(FirewallAlert.user_id == u, FirewallAlert.severity == "Critical"),
            ),
            lambda s, u: scalar(
                s,
                u,
                select(func.avg(PacketEvent.threat_score_contribution)).where(PacketEvent.user_id == u),
            ),
            lambda s, u: scalar(
                s,
                u,
                select(func.max(FirewallAlert.threat_score)).where(FirewallAlert.user_id == u),
            ),
            lambda s, u: s.execute(
                select(FirewallAlert.severity, func.count())
                .where(FirewallAlert.user_id == u)
                .group_by(FirewallAlert.severity)
                .order_by(desc(func.count()))
            ),
            lambda s, u: s.execute(
                select(PacketEvent.protocol, func.count())
                .where(PacketEvent.user_id == u, PacketEvent.protocol.is_not(None))
                .group_by(PacketEvent.protocol)
                .order_by(desc(func.count()))
                .limit(10)
            ),
            lambda s, u: s.execute(
                select(FirewallAlert)
                .where(FirewallAlert.user_id == u)
                .order_by(FirewallAlert.timestamp.desc())
                .limit(10)
            ),
            lambda s, u: s.execute(
                select(day_bucket, func.count(), func.avg(FirewallAlert.threat_score))
                .where(FirewallAlert.user_id == u, FirewallAlert.timestamp >= cutoff)
                .group_by(day_bucket)
                .order_by(day_bucket)
            ),
            lambda s, u: s.execute(
                select(IPReputationCache.country_code, func.count())
                .where(
                    IPReputationCache.user_id == u,
                    IPReputationCache.country_code.is_not(None),
                )
                .group_by(IPReputationCache.country_code)
                .order_by(desc(func.count()))
                .limit(20)
            ),
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
