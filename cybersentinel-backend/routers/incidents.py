"""HTTP routes for security incident management."""

from __future__ import annotations

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import require_role
from core.tenant import get_current_user_id
from db.database import get_db
from schemas.incident import (
    IncidentCreateRequest,
    IncidentResponse,
    IncidentsListResponse,
    IncidentUpdateRequest,
)
from services.incident_service import IncidentService

router = APIRouter(prefix="/api/v1/incidents", tags=["Incident Management"])


def get_incident_service(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> IncidentService:
    return IncidentService(db=db, user_id=get_current_user_id(request))


ServiceDep = Annotated[IncidentService, Depends(get_incident_service)]


@router.post(
    "/create",
    response_model=IncidentResponse,
    summary="Create a security incident",
    dependencies=[Depends(require_role("user"))],
)
async def create_incident(body: IncidentCreateRequest, service: ServiceDep) -> IncidentResponse:
    try:
        return await service.create(body)
    except Exception as exc:
        logger.exception("Error creating incident")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "",
    response_model=IncidentsListResponse,
    summary="List security incidents",
    dependencies=[Depends(require_role("user"))],
)
async def list_incidents(
    service: ServiceDep,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    status_filter: Optional[str] = Query(default=None, alias="status"),
) -> IncidentsListResponse:
    try:
        return await service.list_incidents(page=page, page_size=page_size, status_filter=status_filter)
    except Exception as exc:
        logger.exception("Error listing incidents")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
    summary="Get incident by ID",
    dependencies=[Depends(require_role("user"))],
)
async def get_incident(incident_id: str, service: ServiceDep) -> IncidentResponse:
    incident = await service.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    return IncidentResponse(incident=incident)


@router.patch(
    "/{incident_id}",
    response_model=IncidentResponse,
    summary="Update incident status or notes",
    dependencies=[Depends(require_role("user"))],
)
async def update_incident(
    incident_id: str,
    body: IncidentUpdateRequest,
    service: ServiceDep,
) -> IncidentResponse:
    result = await service.update(incident_id, body)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    return result
