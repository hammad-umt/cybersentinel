"""
HTTP routes for the Security Copilot investigation assistant.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import require_role
from core.tenant import get_current_user_id
from db.database import get_db
from schemas.copilot import CopilotAnswerResponse, CopilotQuestionRequest
from services.copilot_service import CopilotService

router = APIRouter(prefix="/api/v1/copilot", tags=["Security Copilot"])


def get_copilot_service(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> CopilotService:
    return CopilotService(db=db, user_id=get_current_user_id(request))


ServiceDep = Annotated[CopilotService, Depends(get_copilot_service)]


@router.post(
    "/ask",
    response_model=CopilotAnswerResponse,
    summary="Ask a data-grounded security investigation question",
    dependencies=[Depends(require_role("user"))],
)
@router.post(
    "/query",
    response_model=CopilotAnswerResponse,
    summary="Alias for /ask (hidden from docs)",
    dependencies=[Depends(require_role("user"))],
    include_in_schema=False,
)
async def ask_copilot(
    body: CopilotQuestionRequest,
    service: ServiceDep,
) -> CopilotAnswerResponse:
    try:
        return await service.answer(body)
    except Exception as exc:
        logger.exception("Unexpected error in ask_copilot")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
