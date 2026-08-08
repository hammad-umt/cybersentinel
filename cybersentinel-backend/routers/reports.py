"""
routers/reports.py

Admin-gated PDF report exports.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import require_role
from core.tenant import get_current_user_id
from db.database import get_db
from services.report_service import ReportService

router = APIRouter(
    prefix="/api/v1/reports",
    tags=["Reports"],
    dependencies=[Depends(require_role("user"))],
)


def get_report_service(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> ReportService:
    return ReportService(db=db, user_id=get_current_user_id(request))


ReportServiceDep = Annotated[ReportService, Depends(get_report_service)]


@router.get(
    "/summary.pdf",
    summary="Download SOC summary PDF report",
    response_class=StreamingResponse,
)
@router.get(
    "/pdf",
    summary="Alias for /summary.pdf (hidden from docs)",
    response_class=StreamingResponse,
    include_in_schema=False,
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


@router.get(
    "/incident/{incident_id}",
    summary="Get incident report metadata (JSON)",
)
async def get_incident_report(
    incident_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    from services.incident_service import IncidentService

    incident = await IncidentService(db, get_current_user_id(request)).get(incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    return {"success": True, "incident": incident.model_dump()}


@router.get(
    "/export/pdf/{incident_id}",
    summary="Download forensic PDF for one incident",
    response_class=StreamingResponse,
)
async def export_incident_pdf(incident_id: str, service: ReportServiceDep) -> StreamingResponse:
    try:
        pdf_bytes = await service.incident_pdf(incident_id)
        if pdf_bytes is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}.pdf"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error in export_incident_pdf")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/export/csv/{incident_id}",
    summary="Download incident evidence as CSV",
    response_class=StreamingResponse,
)
async def export_incident_csv(incident_id: str, service: ReportServiceDep) -> StreamingResponse:
    try:
        csv_text = await service.incident_csv(incident_id)
        if csv_text is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
        return StreamingResponse(
            iter([csv_text.encode("utf-8")]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}.csv"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error in export_incident_csv")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
