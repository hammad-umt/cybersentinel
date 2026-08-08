"""
HTTP routes for firewall log analysis and alert management.
"""

from __future__ import annotations

import csv
import io
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.security import require_role
from core.tenant import get_current_user_id
from db.database import get_db
from models.loader import ModelNotAvailableError
from schemas.firewall import (
    AckResponse,
    FirewallAlertsResponse,
    FirewallAnalyzeResponse,
    FirewallIngestRequest,
    FirewallIngestResponse,
)
from core.severity import translate_firewall_severity
from schemas.capture import FirewallMonitorRequest, FirewallMonitorResponse
from schemas.threat_intel import EnrichedThreatContext
from services.firewall_service import FirewallService
from services.packet_capture_service import PacketCaptureService
from services.threat_intel_service import ThreatIntelService

router = APIRouter(prefix="/api/v1/firewall", tags=["Firewall Analysis"])

ALLOWED_LOG_SUFFIXES = {".log", ".txt", ".csv"}


def get_firewall_service(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> FirewallService:
    return FirewallService(
        registry=request.app.state.models,
        db=db,
        user_id=get_current_user_id(request),
    )


ServiceDep = Annotated[FirewallService, Depends(get_firewall_service)]


def get_capture_service(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> PacketCaptureService:
    return PacketCaptureService(
        registry=request.app.state.models,
        db=db,
        user_id=get_current_user_id(request),
    )


def get_threat_intel_service(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> ThreatIntelService:
    return ThreatIntelService(db=db, user_id=get_current_user_id(request))


CaptureServiceDep = Annotated[PacketCaptureService, Depends(get_capture_service)]
IntelServiceDep = Annotated[ThreatIntelService, Depends(get_threat_intel_service)]


@router.post(
    "/analyze",
    response_model=FirewallAnalyzeResponse,
    summary="Analyze an uploaded firewall log",
    dependencies=[Depends(require_role("user"))],
)
@router.post(
    "/upload",
    response_model=FirewallAnalyzeResponse,
    summary="Alias for /analyze (hidden from docs)",
    dependencies=[Depends(require_role("user"))],
    include_in_schema=False,
)
async def analyze_firewall_log(
    service: ServiceDep,
    file: UploadFile = File(..., description="Windows pfirewall, Linux iptables/UFW, or CSV-like log file"),
    source: str = Query(default="auto", pattern="^(auto|windows|iptables|linux)$"),
    clustering_algorithm: Optional[str] = Query(
        default=None,
        description="kmeans | dbscan",
    ),
) -> FirewallAnalyzeResponse:
    filename = file.filename or "firewall.log"
    suffix = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ".log"
    if suffix not in ALLOWED_LOG_SUFFIXES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .log, .txt, and .csv firewall log files are supported.",
        )

    try:
        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")
        if len(contents) > settings.max_upload_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds {settings.MAX_UPLOAD_SIZE_MB} MB upload limit.",
            )
        return await service.analyze_file(
            contents,
            filename=filename,
            source=source,
            clustering_algorithm=clustering_algorithm,
        )
    except ModelNotAvailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in analyze_firewall_log")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/ingest",
    response_model=FirewallIngestResponse,
    summary="Ingest one realtime firewall event",
    dependencies=[Depends(require_role("user"))],
)
async def ingest_firewall_event(
    body: FirewallIngestRequest,
    service: ServiceDep,
) -> FirewallIngestResponse:
    try:
        return await service.ingest_realtime(body.event)
    except ModelNotAvailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in ingest_firewall_event")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/alerts",
    response_model=FirewallAlertsResponse,
    summary="Get paginated firewall alerts",
    dependencies=[Depends(require_role("user"))],
)
async def get_alerts(
    service: ServiceDep,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = Query(default=None, description="Low | Medium | High | Critical"),
    unacknowledged_only: bool = Query(default=False),
) -> FirewallAlertsResponse:
    try:
        return await service.get_alerts(
            page=page,
            page_size=page_size,
            severity_filter=severity,
            unacknowledged_only=unacknowledged_only,
        )
    except Exception as exc:
        logger.exception("Unexpected error in get_alerts")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/alerts.csv",
    summary="Export firewall alerts as CSV",
    dependencies=[Depends(require_role("analyst"))],
    response_class=StreamingResponse,
)
async def export_alerts_csv(
    service: ServiceDep,
    severity: Optional[str] = Query(default=None, description="Low | Medium | High | Critical"),
    unacknowledged_only: bool = Query(default=False),
) -> StreamingResponse:
    try:
        rows = await service.fetch_alerts_for_export(
            severity_filter=severity,
            unacknowledged_only=unacknowledged_only,
        )
        csv_bytes = _firewall_alerts_to_csv(rows).encode("utf-8")
        return StreamingResponse(
            iter([csv_bytes]),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="firewall-alerts.csv"'},
        )
    except Exception as exc:
        logger.exception("Unexpected error in export_alerts_csv")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


def _firewall_alerts_to_csv(rows) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id",
        "timestamp",
        "src_ip",
        "threat_score",
        "anomaly_score",
        "heuristic_score",
        "severity",
        "cluster_label",
        "attack_signals",
        "consensus_anomaly",
        "acknowledged",
        "source_session",
    ])
    for row in rows:
        writer.writerow([
            row.id,
            row.timestamp,
            row.src_ip,
            row.threat_score,
            row.anomaly_score,
            row.heuristic_score,
            translate_firewall_severity(row.severity),
            row.cluster_label,
            row.attack_signals,
            row.consensus_anomaly,
            row.acknowledged,
            row.source_session or "",
        ])
    return output.getvalue()


@router.patch(
    "/alerts/{alert_id}/acknowledge",
    response_model=AckResponse,
    summary="Acknowledge one firewall alert",
    dependencies=[Depends(require_role("user"))],
)
async def acknowledge_alert(alert_id: str, service: ServiceDep) -> AckResponse:
    try:
        return await service.acknowledge_alert(alert_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in acknowledge_alert")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/monitor/start",
    response_model=FirewallMonitorResponse,
    summary="Start real-time Windows firewall log monitor",
    description=(
        "Tails pfirewall.log and feeds every new entry into the unsupervised "
        "anomaly detection pipeline. Alerts appear in /api/v1/firewall/alerts. "
        "Run as Administrator to read the system firewall log."
    ),
    dependencies=[Depends(require_role("user"))],
)
async def start_firewall_monitor(
    body: FirewallMonitorRequest,
    service: CaptureServiceDep,
) -> FirewallMonitorResponse:
    try:
        return await service.start_firewall_monitor(body)
    except ModelNotAvailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("Error starting firewall monitor")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/monitor/stop",
    response_model=FirewallMonitorResponse,
    summary="Stop real-time firewall log monitor",
    dependencies=[Depends(require_role("user"))],
)
async def stop_firewall_monitor(service: CaptureServiceDep) -> FirewallMonitorResponse:
    try:
        return await service.stop_firewall_monitor()
    except Exception as exc:
        logger.exception("Error stopping firewall monitor")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/monitor/status",
    response_model=FirewallMonitorResponse,
    summary="Get firewall monitor status",
    dependencies=[Depends(require_role("user"))],
)
async def get_firewall_monitor_status(service: CaptureServiceDep) -> FirewallMonitorResponse:
    try:
        return await service.get_firewall_monitor_status()
    except Exception as exc:
        logger.exception("Error fetching firewall monitor status")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/intel/ip/{ip}",
    response_model=EnrichedThreatContext,
    dependencies=[Depends(require_role("analyst"))],
    summary="Get threat intelligence context for an IP",
)
async def get_ip_intel(ip: str, service: IntelServiceDep) -> EnrichedThreatContext:
    try:
        return await service.enrich(ip)
    except Exception as exc:
        logger.exception("Unexpected error in get_ip_intel")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
