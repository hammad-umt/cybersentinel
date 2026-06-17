"""
routers/capture.py

HTTP routes for live packet capture.

Endpoints:
  GET  /api/v1/capture/interfaces          — list network interfaces
  POST /api/v1/capture/start               — start live packet capture
  POST /api/v1/capture/stop                — stop capture
  GET  /api/v1/capture/status              — capture status + counts
  GET  /api/v1/capture/packets             — get captured + classified packets
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import require_admin_api_key
from db.database import get_db
from schemas.capture import CapturedPacketsResponse, CaptureStartRequest, CaptureStatusResponse, InterfacesResponse
from services.packet_capture_service import PacketCaptureService

router = APIRouter(prefix="/api/v1/capture", tags=["Live Capture"])


def get_capture_service(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> PacketCaptureService:
    return PacketCaptureService(registry=request.app.state.models, db=db)


ServiceDep = Annotated[PacketCaptureService, Depends(get_capture_service)]


# ---------------------------------------------------------------------------
# Network interfaces
# ---------------------------------------------------------------------------

@router.get(
    "/interfaces",
    response_model=InterfacesResponse,
    summary="List available network interfaces for capture",
)
async def list_interfaces(service: ServiceDep) -> InterfacesResponse:
    try:
        interfaces, scapy_ok, tshark_ok = service.list_interfaces()
        return InterfacesResponse(
            interfaces=interfaces,
            tshark_available=tshark_ok,
            scapy_available=scapy_ok,
        )
    except Exception as exc:
        logger.exception("Error listing interfaces")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


# ---------------------------------------------------------------------------
# Packet capture
# ---------------------------------------------------------------------------

@router.post(
    "/start",
    response_model=CaptureStatusResponse,
    summary="Start live packet capture",
    description=(
        "Starts capturing packets on the specified network interface using Scapy "
        "(requires Npcap on Windows) or TShark (requires Wireshark). "
        "Run the backend as Administrator for raw socket access."
    ),
    dependencies=[Depends(require_admin_api_key)],
)
async def start_capture(
    body: CaptureStartRequest,
    service: ServiceDep,
) -> CaptureStatusResponse:
    try:
        result = await service.start_capture(body)
        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=result.message,
            )
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error starting capture")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


@router.post(
    "/stop",
    response_model=CaptureStatusResponse,
    summary="Stop live packet capture",
    dependencies=[Depends(require_admin_api_key)],
)
async def stop_capture(service: ServiceDep) -> CaptureStatusResponse:
    try:
        return await service.stop_capture()
    except Exception as exc:
        logger.exception("Error stopping capture")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


@router.get(
    "/status",
    response_model=CaptureStatusResponse,
    summary="Get current capture status and packet counts",
)
async def get_capture_status(service: ServiceDep) -> CaptureStatusResponse:
    try:
        return await service.get_status()
    except Exception as exc:
        logger.exception("Error fetching capture status")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


@router.get(
    "/packets",
    response_model=CapturedPacketsResponse,
    summary="Get all captured and classified packets",
    description="Returns all packets captured in the current session with ML predictions.",
    dependencies=[Depends(require_admin_api_key)],
)
async def get_packets(service: ServiceDep) -> CapturedPacketsResponse:
    try:
        return await service.get_packets()
    except Exception as exc:
        logger.exception("Error fetching captured packets")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )

