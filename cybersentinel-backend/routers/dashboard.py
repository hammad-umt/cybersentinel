"""
HTTP routes for SOC dashboard data.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_db
from schemas.dashboard import DashboardSummary
from services.dashboard_service import DashboardService

router = APIRouter(prefix="/api/v1/dashboard", tags=["SOC Dashboard"])


def get_dashboard_service(db: AsyncSession = Depends(get_db)) -> DashboardService:
    return DashboardService(db=db)


ServiceDep = Annotated[DashboardService, Depends(get_dashboard_service)]


@router.get(
    "/summary",
    response_model=DashboardSummary,
    summary="Get SOC dashboard summary",
)
async def dashboard_summary(service: ServiceDep) -> DashboardSummary:
    try:
        return await service.summary()
    except Exception as exc:
        logger.exception("Unexpected error in dashboard_summary")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
