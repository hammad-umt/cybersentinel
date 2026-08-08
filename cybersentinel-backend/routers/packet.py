"""
routers/packet.py

HTTP routes for the supervised packet classification module.
Thin layer - all logic lives in services/packet_service.py.

Endpoints:
  POST /api/v1/packet/classify        — single flow
  POST /api/v1/packet/classify/batch  — batch CSV upload
  GET  /api/v1/packet/events          — paginated history
"""

from __future__ import annotations

import csv
import io
from typing import Annotated, Optional

import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File, status
from fastapi.responses import StreamingResponse
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.security import require_role
from core.tenant import get_current_user_id
from db.database import get_db
from models.loader import ModelNotAvailableError
from schemas.packet import (
    PacketBatchResponse,
    PacketClassifyRequest,
    PacketClassifyResponse,
    PacketEventsResponse,
)
from services.packet_service import PacketService

router = APIRouter(prefix="/api/v1/packet", tags=["Packet Classification"])


# ---------------------------------------------------------------------------
# Dependency — builds the service with the registry and DB session
# ---------------------------------------------------------------------------

def get_packet_service(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> PacketService:
    return PacketService(
        registry=request.app.state.models,
        db=db,
        user_id=get_current_user_id(request),
    )


ServiceDep = Annotated[PacketService, Depends(get_packet_service)]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get(
    "/features",
    summary="Canonical packet feature names (cs-fyp)",
    description="Returns the 23 feature keys required in classify request bodies.",
    dependencies=[Depends(require_role("user"))],
)
async def list_packet_features() -> dict[str, list[str]]:
    from ml_engine.features import FEATURE_NAMES

    return {"features": list(FEATURE_NAMES)}


@router.post(
    "/classify",
    response_model=PacketClassifyResponse,
    summary="Classify a single network flow",
    description=(
        "Send one network flow's 23 canonical features (cs-fyp FEATURE_NAMES) and receive "
        "a Normal / Suspicious / Malicious fused SOC label."
    ),
    dependencies=[Depends(require_role("user"))],
)
async def classify_single(
    body: PacketClassifyRequest,
    service: ServiceDep,
) -> PacketClassifyResponse:
    try:
        return await service.classify_single(body.to_flow_input())
    except ModelNotAvailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error in classify_single")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/classify/batch",
    response_model=PacketBatchResponse,
    summary="Classify flows from an uploaded CSV file",
    description=(
        "Upload a CSV file containing network flow records. "
        "Column names can be CICIDS2017-style or live-flow aliases. "
        "Returns per-flow predictions and summary counts for the dashboard."
    ),
    dependencies=[Depends(require_role("user"))],
)
async def classify_batch_csv(
    service: ServiceDep,
    file: UploadFile = File(..., description="CSV file of network flows"),
) -> PacketBatchResponse:
    # Validate file type
    filename = file.filename or ""
    if not filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only CSV files are supported.",
        )

    try:
        contents = await file.read()
        if not contents:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded CSV is empty.",
            )
        if len(contents) > settings.max_upload_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds {settings.MAX_UPLOAD_SIZE_MB} MB upload limit.",
            )
        df = pd.read_csv(io.BytesIO(contents), low_memory=False)

        if df.empty:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded CSV is empty.",
            )
        if len(df) > settings.MAX_BATCH_FLOWS:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"CSV contains {len(df)} rows; maximum is {settings.MAX_BATCH_FLOWS}.",
            )

        from ml_engine.column_mapping import csv_row_to_feature_vector
        from schemas.packet import FlowFeatureVector, PacketClassifyRequest

        flows = []
        for _, row in df.iterrows():
            clean_row = {
                key: (None if pd.isna(value) else value)
                for key, value in row.to_dict().items()
            }
            feature_values = csv_row_to_feature_vector(clean_row)
            flows.append(
                PacketClassifyRequest(
                    features=FlowFeatureVector.model_validate(feature_values),
                    source_ip=clean_row.get("src_ip") or clean_row.get("source_ip"),
                    dest_ip=clean_row.get("dst_ip") or clean_row.get("dest_ip"),
                    dest_port=clean_row.get("dst_port") or clean_row.get("dest_port"),
                    protocol=str(clean_row.get("protocol") or "TCP"),
                ).to_flow_input()
            )

        return await service.classify_batch(flows, source="batch")

    except ModelNotAvailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error in classify_batch_csv")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/events",
    response_model=PacketEventsResponse,
    summary="Get paginated packet classification history",
    description="Returns all stored packet events. Filter by prediction label.",
    dependencies=[Depends(require_role("user"))],
)
async def get_events(
    service: ServiceDep,
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=500, description="Results per page"),
    prediction: Optional[str] = Query(
        default=None,
        description="Filter by label: Normal | Suspicious | Malicious",
    ),
) -> PacketEventsResponse:
    try:
        return await service.get_events(
            page=page,
            page_size=page_size,
            prediction_filter=prediction,
        )
    except Exception as exc:
        logger.exception("Unexpected error in get_events")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/events.csv",
    summary="Export packet classification history as CSV",
    response_class=StreamingResponse,
    dependencies=[Depends(require_role("user"))],
)
async def export_events_csv(
    service: ServiceDep,
    prediction: Optional[str] = Query(
        default=None,
        description="Filter by label: Normal | Suspicious | Malicious",
    ),
) -> StreamingResponse:
    try:
        rows = await service.fetch_events_for_export(prediction_filter=prediction)
        csv_bytes = _packet_events_to_csv(rows).encode("utf-8")
        return StreamingResponse(
            iter([csv_bytes]),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="packet-events.csv"'},
        )
    except Exception as exc:
        logger.exception("Unexpected error in export_events_csv")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


def _packet_events_to_csv(rows) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id",
        "timestamp",
        "src_ip",
        "dst_ip",
        "dst_port",
        "protocol",
        "prediction",
        "ml_confidence",
        "risk_score",
        "source",
    ])
    for row in rows:
        writer.writerow([
            row.id,
            row.timestamp,
            row.src_ip or "",
            row.dst_ip or "",
            row.dst_port or "",
            row.protocol or "",
            row.prediction,
            row.confidence,
            row.threat_score_contribution,
            row.source,
        ])
    return output.getvalue()
