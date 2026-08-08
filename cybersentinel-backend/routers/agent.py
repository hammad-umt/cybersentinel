"""HTTP routes for remote monitoring agents."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import require_role
from core.tenant import get_current_user_id
from db.database import get_db
from schemas.agent import (
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentStatusResponse,
    AgentTelemetryRequest,
    AgentTelemetryResponse,
)
from services.agent_service import AgentService

router = APIRouter(prefix="/api/v1/agent", tags=["Monitoring Agents"])


def get_agent_service(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AgentService:
    return AgentService(
        db=db,
        user_id=get_current_user_id(request),
        registry=request.app.state.models,
    )


ServiceDep = Annotated[AgentService, Depends(get_agent_service)]


@router.post(
    "/register",
    response_model=AgentRegisterResponse,
    summary="Register a remote monitoring agent",
    dependencies=[Depends(require_role("user"))],
)
async def register_agent(body: AgentRegisterRequest, service: ServiceDep) -> AgentRegisterResponse:
    try:
        return await service.register(body)
    except Exception as exc:
        logger.exception("Error registering agent")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/telemetry",
    response_model=AgentTelemetryResponse,
    summary="Ingest telemetry from a registered agent",
)
async def ingest_telemetry(
    body: AgentTelemetryRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
) -> AgentTelemetryResponse:
    from db.models import MonitoringAgent
    from sqlalchemy import select
    import hashlib

    key_hash = hashlib.sha256(x_agent_key.encode("utf-8")).hexdigest()
    row = (
        await db.execute(
            select(MonitoringAgent).where(
                MonitoringAgent.agent_id == body.agent_id,
                MonitoringAgent.api_key_hash == key_hash,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent credentials.")

    service = AgentService(
        db=db,
        user_id=row.user_id,
        registry=request.app.state.models,
    )
    try:
        return await service.ingest_telemetry(body, agent_row=row)
    except Exception as exc:
        logger.exception("Error ingesting agent telemetry")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/status",
    response_model=AgentStatusResponse,
    summary="List registered agents and their status",
    dependencies=[Depends(require_role("user"))],
)
async def agent_status(service: ServiceDep) -> AgentStatusResponse:
    try:
        return await service.list_status()
    except Exception as exc:
        logger.exception("Error fetching agent status")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
