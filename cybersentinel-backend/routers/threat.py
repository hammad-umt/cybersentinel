"""
routers/threat.py

HTTP routes for CyberSentinel unified threat scoring.
These endpoints expose the weighted ensemble score used to connect packet ML,
firewall anomaly detection, and external threat intelligence.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import require_role
from db.database import get_db
from schemas.auth import ThreatQueueRequest, ThreatQueueResponse
from schemas.threat_score import TopThreatsResponse, UnifiedThreatScore
from services.threat_scoring_service import ThreatScoringService

router = APIRouter(prefix="/api/v1/threat", tags=["Unified Threat Scoring"])


def get_threat_scoring_service(
    db: AsyncSession = Depends(get_db),
) -> ThreatScoringService:
    return ThreatScoringService(db=db)


ServiceDep = Annotated[ThreatScoringService, Depends(get_threat_scoring_service)]


@router.post(
    "/queue",
    response_model=ThreatQueueResponse,
    summary="Queue IP addresses for background threat scoring",
    dependencies=[Depends(require_role("user"))],
)
async def queue_ip_analysis(
    body: ThreatQueueRequest,
    background_tasks: BackgroundTasks,
) -> ThreatQueueResponse:
    from db.database import AsyncSessionLocal

    cleaned = [ip.strip() for ip in body.ips if ip.strip()]
    if not cleaned:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid IP addresses provided.")

    async def run_queue():
        async with AsyncSessionLocal() as db:
            service = ThreatScoringService(db=db)
            for ip in cleaned:
                try:
                    await service.score(ip, {"source": "queue"})
                except Exception:
                    pass

    background_tasks.add_task(run_queue)
    return ThreatQueueResponse(
        queued=len(cleaned),
        message=f"Queued {len(cleaned)} IP(s) for background threat analysis.",
    )


@router.get(
    "/score/{ip}",
    response_model=UnifiedThreatScore,
    summary="Get unified threat score for an IP",
    dependencies=[Depends(require_role("user"))],
)
async def score_ip(ip: str, service: ServiceDep) -> UnifiedThreatScore:
    try:
        return await service.score(ip, {"source": "api"})
    except Exception as exc:
        logger.exception("Unexpected error in score_ip")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/top",
    response_model=TopThreatsResponse,
    summary="Get top IPs by unified threat score",
    dependencies=[Depends(require_role("user"))],
)
async def top_threats(
    service: ServiceDep,
    limit: int = Query(default=20, ge=1, le=100),
) -> TopThreatsResponse:
    try:
        return await service.top(limit=limit)
    except Exception as exc:
        logger.exception("Unexpected error in top_threats")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
