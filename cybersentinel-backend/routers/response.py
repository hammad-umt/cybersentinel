"""
HTTP routes for the Threat Response Center.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import require_role
from db.database import get_db
from schemas.response import (
    ResponseActionRequest,
    ResponseActionResponse,
    ResponseActionsResponse,
)
from services.response_service import ResponseService

router = APIRouter(prefix="/api/v1/response", tags=["Threat Response Center"])


def get_response_service(db: AsyncSession = Depends(get_db)) -> ResponseService:
    return ResponseService(db=db)


ServiceDep = Annotated[ResponseService, Depends(get_response_service)]


@router.post(
    "/actions",
    response_model=ResponseActionResponse,
    summary="Record or execute a threat response action",
    dependencies=[Depends(require_role("admin"))],
)
async def create_response_action(
    body: ResponseActionRequest,
    service: ServiceDep,
) -> ResponseActionResponse:
    try:
        return await service.create_action(body)
    except Exception as exc:
        logger.exception("Unexpected error in create_response_action")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/actions",
    response_model=ResponseActionsResponse,
    summary="Get response action audit log",
)
async def list_response_actions(
    service: ServiceDep,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
) -> ResponseActionsResponse:
    try:
        return await service.list_actions(page=page, page_size=page_size)
    except Exception as exc:
        logger.exception("Unexpected error in list_response_actions")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
