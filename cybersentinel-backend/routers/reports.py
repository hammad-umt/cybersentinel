"""
routers/reports.py

Admin-gated PDF report exports.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import require_role
from db.database import get_db
from services.report_service import ReportService

router = APIRouter(
    prefix="/api/v1/reports",
    tags=["Reports"],
    dependencies=[Depends(require_role("user"))],
)


def get_report_service(db: AsyncSession = Depends(get_db)) -> ReportService:
    return ReportService(db=db)


ReportServiceDep = Annotated[ReportService, Depends(get_report_service)]


@router.get(
    "/summary.pdf",
    summary="Download SOC summary PDF report",
    response_class=StreamingResponse,
)
async def download_summary_pdf(service: ReportServiceDep) -> StreamingResponse:
    try:
        pdf_bytes = await service.summary_pdf()
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="cybersentinel-summary.pdf"'},
        )
    except Exception as exc:
        logger.exception("Unexpected error in download_summary_pdf")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
