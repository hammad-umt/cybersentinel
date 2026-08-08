"""
HTTP routes for SOC dashboard data.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import require_role
from core.ttl_cache import get_or_set
from core.tenant import get_current_user_id
from db.database import get_db
from schemas.dashboard import (
    AttackDistribution,
    DashboardSummary,
    IncidentStats,
    ThreatTrends,
)
from services.dashboard_service import DashboardService

router = APIRouter(prefix="/api/v1/dashboard", tags=["SOC Dashboard"])


def get_dashboard_service(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> DashboardService:
    return DashboardService(db=db, user_id=get_current_user_id(request))


ServiceDep = Annotated[DashboardService, Depends(get_dashboard_service)]


@router.get(
    "/summary",
    response_model=DashboardSummary,
    summary="Get SOC dashboard summary",
    dependencies=[Depends(require_role("user"))],
)
async def dashboard_summary(request: Request, service: ServiceDep) -> DashboardSummary:
    user_id = get_current_user_id(request)
    try:
        return await get_or_set(
            f"dashboard:summary:{user_id}",
            ttl_seconds=5.0,
            factory=service.summary,
        )
    except Exception as exc:
        logger.exception("Unexpected error in dashboard_summary")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/incidents",
    response_model=IncidentStats,
    summary="Incident statistics for SOC dashboard",
    dependencies=[Depends(require_role("user"))],
)
async def dashboard_incidents(service: ServiceDep) -> IncidentStats:
    try:
        return await service.incident_stats()
    except Exception as exc:
        logger.exception("Unexpected error in dashboard_incidents")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/attacks",
    response_model=AttackDistribution,
    summary="Attack type and MITRE distribution",
    dependencies=[Depends(require_role("user"))],
)
async def dashboard_attacks(service: ServiceDep) -> AttackDistribution:
    try:
        return await service.attack_distribution()
    except Exception as exc:
        logger.exception("Unexpected error in dashboard_attacks")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/trends",
    response_model=ThreatTrends,
    summary="Threat score trends and top attackers",
    dependencies=[Depends(require_role("user"))],
)
async def dashboard_trends(service: ServiceDep) -> ThreatTrends:
    try:
        return await service.threat_trends()
    except Exception as exc:
        logger.exception("Unexpected error in dashboard_trends")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/incidents",
    response_model=IncidentStats,
    summary="Incident statistics for SOC dashboard",
    dependencies=[Depends(require_role("user"))],
)
async def dashboard_incidents(service: ServiceDep) -> IncidentStats:
    try:
        return await service.incident_stats()
    except Exception as exc:
        logger.exception("Unexpected error in dashboard_incidents")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/attacks",
    response_model=AttackDistribution,
    summary="Attack type and MITRE distribution",
    dependencies=[Depends(require_role("user"))],
)
async def dashboard_attacks(service: ServiceDep) -> AttackDistribution:
    try:
        return await service.attack_distribution()
    except Exception as exc:
        logger.exception("Unexpected error in dashboard_attacks")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/trends",
    response_model=ThreatTrends,
    summary="Threat score trends and top attackers",
    dependencies=[Depends(require_role("user"))],
)
async def dashboard_trends(service: ServiceDep) -> ThreatTrends:
    try:
        return await service.threat_trends()
    except Exception as exc:
        logger.exception("Unexpected error in dashboard_trends")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
