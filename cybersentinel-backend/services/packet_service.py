"""
services/packet_service.py

Business logic for the supervised packet classification module.

Responsibilities:
  1. Convert incoming Pydantic schema objects into a pandas DataFrame
     that CyberSentinelPacketClassifier.predict() expects
  2. Call the classifier
  3. Convert raw classifier output into clean response schemas
  4. Persist every result to the packet_events DB table
  5. Compute threat score contribution for each prediction

Never imports from routers — routers call services, not the other way around.
"""

from __future__ import annotations

import math
from typing import List

import pandas as pd
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select

from core.config import settings
from db.models import PacketEvent
from models.loader import ModelRegistry
from schemas.packet import (
    FlowFeatures,
    PacketBatchResponse,
    PacketClassifyResponse,
    PacketEventOut,
    PacketEventsResponse,
    PacketPrediction,
)


# ---------------------------------------------------------------------------
# Threat score mapping
# Converts classifier output → 0-100 score contribution for ensemble later.
# ---------------------------------------------------------------------------

_PREDICTION_BASE_SCORE: dict[str, float] = {
    "Normal": 0.0,
    "Suspicious": 50.0,
    "Malicious": 85.0,
    "Insufficient Evidence": 0.0,
}


def _threat_score(
    prediction: str,
    confidence: float,
    prob_suspicious: float | None = None,
    prob_malicious: float | None = None,
    feature_coverage: float | None = None,
) -> float:
    """
    Score risk from attack probability, not only the winning class.

    This prevents a Normal argmax from erasing meaningful Suspicious/Malicious
    probability mass. Low feature coverage reduces the score because the ML
    evidence itself is weak.
    """
    if not math.isfinite(confidence):
        confidence = 0.0
    confidence = max(0.0, min(confidence, 1.0))

    suspicious = max(0.0, min(prob_suspicious or 0.0, 1.0))
    malicious = max(0.0, min(prob_malicious or 0.0, 1.0))
    probability_score = 100.0 * ((0.35 * suspicious) + (0.75 * malicious))

    base = _PREDICTION_BASE_SCORE.get(prediction, 0.0) * confidence
    coverage_factor = max(0.0, min(feature_coverage if feature_coverage is not None else 1.0, 1.0))
    return round(min(100.0, max(base, probability_score) * coverage_factor), 2)


# ---------------------------------------------------------------------------
# PacketService
# ---------------------------------------------------------------------------

class PacketService:
    """
    Wraps CyberSentinelPacketClassifier for use in FastAPI route handlers.

    Usage:
        service = PacketService(registry=request.app.state.models, db=db)
        response = await service.classify_single(request_body)
    """

    def __init__(self, registry: ModelRegistry, db: AsyncSession):
        self.registry = registry
        self.db = db

    # ------------------------------------------------------------------
    # Public API — called by routers
    # ------------------------------------------------------------------

    async def classify_single(
        self,
        flow: FlowFeatures,
        model_type: str | None = None,
    ) -> PacketClassifyResponse:
        """Classify one flow and persist the result."""
        classifier = self.registry.require_packet_classifier(model_type)
        df = _flows_to_dataframe([flow])

        logger.debug("Classifying single flow from src_ip={}", flow.src_ip)
        raw_results = classifier.predict(df)
        row = raw_results.iloc[0]

        prediction = _parse_prediction(row)
        event_id = await self._save_event(prediction, flow)
        prediction.event_id = event_id

        return PacketClassifyResponse(
            success=True,
            result=prediction,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
        )

    async def classify_batch(
        self,
        flows: List[FlowFeatures],
        source: str = "batch",
        model_type: str | None = None,
    ) -> PacketBatchResponse:
        """Classify a list of flows (CSV upload) and persist all results."""
        classifier = self.registry.require_packet_classifier(model_type)
        df = _flows_to_dataframe(flows)

        logger.info("Classifying batch of {} flows", len(flows))
        raw_results = classifier.predict(df)

        predictions: List[PacketPrediction] = []
        for pos, (_, row) in enumerate(raw_results.iterrows()):
            pred = _parse_prediction(row)
            flow = flows[pos] if pos < len(flows) else None
            event_id = await self._save_event(pred, flow, source=source)
            pred.event_id = event_id
            predictions.append(pred)

        # Flush all inserts in one commit via the session
        await self.db.flush()

        return _build_batch_response(predictions)

    async def get_events(
        self,
        page: int = 1,
        page_size: int = 50,
        prediction_filter: str | None = None,
    ) -> PacketEventsResponse:
        """
        Return paginated packet events from DB.
        Flutter uses this for the history table and for filtering by label.
        """
        page_size = min(page_size, settings.MAX_PAGE_SIZE)
        offset = (page - 1) * page_size

        query = select(PacketEvent).order_by(PacketEvent.timestamp.desc())
        count_query = select(func.count()).select_from(PacketEvent)

        if prediction_filter:
            query = query.where(PacketEvent.prediction == prediction_filter)
            count_query = count_query.where(PacketEvent.prediction == prediction_filter)

        total_result = await self.db.execute(count_query)
        total = total_result.scalar_one()

        result = await self.db.execute(query.offset(offset).limit(page_size))
        rows = result.scalars().all()

        return PacketEventsResponse(
            success=True,
            total=total,
            page=page,
            page_size=page_size,
            events=[PacketEventOut.model_validate(row) for row in rows],
        )

    async def fetch_events_for_export(
        self,
        prediction_filter: str | None = None,
    ) -> list[PacketEvent]:
        """Return all packet events matching the export filters."""
        query = select(PacketEvent).order_by(PacketEvent.timestamp.desc())

        if prediction_filter:
            query = query.where(PacketEvent.prediction == prediction_filter)

        result = await self.db.execute(query.limit(settings.MAX_PAGE_SIZE * 20))
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _save_event(
        self,
        prediction: PacketPrediction,
        flow: FlowFeatures | None,
        source: str = "single",
    ) -> str:
        """Persist one PacketPrediction to the packet_events table."""
        event = PacketEvent(
            src_ip=flow.src_ip if flow else None,
            dst_ip=flow.dst_ip if flow else None,
            dst_port=flow.dst_port if flow else None,
            protocol=flow.protocol if flow else None,
            prediction=prediction.prediction,
            confidence=prediction.confidence,
            prob_normal=prediction.prob_normal,
            prob_suspicious=prediction.prob_suspicious,
            prob_malicious=prediction.prob_malicious,
            feature_coverage=prediction.feature_coverage,
            missing_feature_count=prediction.missing_feature_count,
            traffic_schema=prediction.traffic_schema,
            threat_score_contribution=prediction.threat_score_contribution,
            source=source,
        )
        self.db.add(event)
        # Flush so the ID is populated without committing the transaction.
        # The router's get_db() dependency commits after the handler returns.
        await self.db.flush()
        await self.db.refresh(event)
        return event.id


# ---------------------------------------------------------------------------
# Pure helper functions — no DB or ML state
# ---------------------------------------------------------------------------

def _flows_to_dataframe(flows: List[FlowFeatures]) -> pd.DataFrame:
    """
    Convert a list of FlowFeatures Pydantic objects into a DataFrame
    using the CICIDS2017 column names the classifier expects.

    model_dump(by_alias=True) produces keys like "Flow Duration" instead
    of "flow_duration" because FlowFeatures uses alias= on each field.
    Metadata-only fields (src_ip, dst_ip, etc.) are excluded because
    they have no alias and the classifier ignores unknown columns anyway.
    """
    records = []
    for flow in flows:
        # by_alias=True gives us CICIDS2017 column names
        record = flow.model_dump(by_alias=True, exclude_none=False)
        # Remove display-only fields that aren't ML features
        for meta_field in ("src_ip", "dst_ip", "dst_port", "protocol"):
            record.pop(meta_field, None)
        record = {
            key: (None if _is_nan(value) else value)
            for key, value in record.items()
        }
        records.append(record)
    return pd.DataFrame(records)


def _parse_prediction(row: pd.Series) -> PacketPrediction:
    """
    Convert one row from classifier.predict() output into a PacketPrediction.
    Handles missing probability columns gracefully.
    """
    prediction = str(row.get("prediction", "Normal"))
    confidence = _safe_float(row.get("confidence")) or 0.0

    # Probability columns — present only if classifier supports predict_proba
    prob_normal = _safe_float(row.get("prob_Normal"))
    prob_suspicious = _safe_float(row.get("prob_Suspicious"))
    prob_malicious = _safe_float(row.get("prob_Malicious"))

    feature_coverage = _safe_float(row.get("feature_coverage"))
    missing_count_raw = row.get("missing_feature_count")
    missing_count = int(missing_count_raw) if missing_count_raw is not None and not _is_nan(missing_count_raw) else None
    traffic_schema = str(row.get("traffic_schema", "")) or None

    if traffic_schema == "insufficient-live-flow-features":
        prediction = "Insufficient Evidence"
        confidence = 0.0

    score = _threat_score(
        prediction,
        confidence,
        prob_suspicious=prob_suspicious,
        prob_malicious=prob_malicious,
        feature_coverage=feature_coverage,
    )

    return PacketPrediction(
        prediction=prediction,
        confidence=round(confidence, 4),
        prob_normal=round(prob_normal, 4) if prob_normal is not None else None,
        prob_suspicious=round(prob_suspicious, 4) if prob_suspicious is not None else None,
        prob_malicious=round(prob_malicious, 4) if prob_malicious is not None else None,
        feature_coverage=round(feature_coverage, 4) if feature_coverage is not None else None,
        missing_feature_count=missing_count,
        traffic_schema=traffic_schema,
        threat_score_contribution=score,
    )


def _build_batch_response(predictions: List[PacketPrediction]) -> PacketBatchResponse:
    """Aggregate a list of predictions into a batch response with summary counts."""
    normal = sum(1 for p in predictions if p.prediction == "Normal")
    suspicious = sum(1 for p in predictions if p.prediction == "Suspicious")
    malicious = sum(1 for p in predictions if p.prediction == "Malicious")
    insufficient = sum(1 for p in predictions if p.prediction == "Insufficient Evidence")

    scores = [p.threat_score_contribution for p in predictions]
    avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0

    return PacketBatchResponse(
        success=True,
        total_flows=len(predictions),
        results=predictions,
        normal_count=normal,
        suspicious_count=suspicious,
        malicious_count=malicious,
        insufficient_evidence_count=insufficient,
        avg_threat_score=avg_score,
    )


def _safe_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        f = float(value)
        return f if math.isfinite(f) else None
    except (TypeError, ValueError):
        return None


def _is_nan(value: object) -> bool:
    try:
        return math.isnan(float(value))
    except (TypeError, ValueError):
        return False
