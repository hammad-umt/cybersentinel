"""
routers/intel.py

HTTP routes for VirusTotal file and URL scanning.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from db.database import get_db
from schemas.threat_intel import URLScanRequest, VTResult
from services.threat_intel_service import ThreatIntelService

router = APIRouter(prefix="/api/v1/intel", tags=["Threat Intelligence"])


def get_threat_intel_service(db: AsyncSession = Depends(get_db)) -> ThreatIntelService:
    return ThreatIntelService(db=db)


IntelServiceDep = Annotated[ThreatIntelService, Depends(get_threat_intel_service)]


@router.post(
    "/file",
    response_model=VTResult,
    summary="Scan an uploaded file with VirusTotal",
)
async def scan_file(
    service: IntelServiceDep,
    file: UploadFile = File(..., description="File to hash and scan with VirusTotal"),
) -> VTResult:
    try:
        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")
        if len(contents) > settings.max_upload_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds {settings.MAX_UPLOAD_SIZE_MB} MB upload limit.",
            )
        return await service.check_file(contents)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error in scan_file")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/url",
    response_model=VTResult,
    summary="Scan a URL with VirusTotal",
)
async def scan_url(body: URLScanRequest, service: IntelServiceDep) -> VTResult:
    try:
        return await service.check_url(body.url)
    except Exception as exc:
        logger.exception("Unexpected error in scan_url")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
