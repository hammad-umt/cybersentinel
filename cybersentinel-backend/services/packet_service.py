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
import asyncio
from datetime import datetime, timedelta, timezone
from typing import List

import pandas as pd
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select

from core.config import settings
from db.models import FirewallAlert, PacketEvent
from models.loader import ModelRegistry
from schemas.packet import (
    FlowFeatures,
    PacketBatchResponse,
    PacketClassifyResponse,
    PacketEventOut,
    PacketEventsResponse,
    PacketPrediction,
)
from soc.fusion import FusionInput, SOCFusionEngine
from soc.rules import SOCRuleContext, SOCRuleEngine


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

    def __init__(self, registry: ModelRegistry, db: AsyncSession, user_id: str):
        self.registry = registry
        self.db = db
        self.user_id = user_id
        self.rule_engine = SOCRuleEngine()
        self.fusion_engine = SOCFusionEngine()

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
        packet_detector = self.registry.get_packet_anomaly_detector()

        logger.debug("Classifying single flow from src_ip={} with hybrid SOC pipeline", flow.src_ip)
        rf_task = asyncio.to_thread(classifier.predict, df)
        packet_task = (
            asyncio.to_thread(packet_detector.predict, df)
            if packet_detector is not None
            else asyncio.sleep(0, result=_empty_packet_anomaly_df(df))
        )
        raw_results, packet_results = await asyncio.gather(
            rf_task,
            packet_task,
        )
        firewall_signal = await self._latest_firewall_signal(flow.src_ip)
        port_count = await self._recent_dst_port_count(flow)

        prediction = self._build_soc_prediction(
            rf_row=raw_results.iloc[0],
            packet_row=packet_results.iloc[0],
            firewall_signal=firewall_signal,
            port_count=port_count,
            flow=flow,
            packet_detector_available=packet_detector is not None,
        )
        await self._save_event(prediction, flow)

        return PacketClassifyResponse(
            success=True,
            result=prediction,
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
        packet_detector = self.registry.get_packet_anomaly_detector()

        logger.info("Classifying batch of {} flows with hybrid SOC pipeline", len(flows))
        rf_task = asyncio.to_thread(classifier.predict, df)
        packet_task = (
            asyncio.to_thread(packet_detector.predict, df)
            if packet_detector is not None
            else asyncio.sleep(0, result=_empty_packet_anomaly_df(df))
        )
        raw_results, packet_results = await asyncio.gather(rf_task, packet_task)
        batch_port_counts = _batch_port_counts(flows)

        predictions: List[PacketPrediction] = []
        for pos, (_, row) in enumerate(raw_results.iterrows()):
            flow = flows[pos] if pos < len(flows) else None
            firewall_signal = await self._latest_firewall_signal(flow.src_ip if flow else None)
            port_count = batch_port_counts.get(flow.src_ip or "", 0) if flow else 0
            pred = self._build_soc_prediction(
                rf_row=row,
                packet_row=packet_results.iloc[pos],
                firewall_signal=firewall_signal,
                port_count=port_count,
                flow=flow,
                packet_detector_available=packet_detector is not None,
            )
            await self._save_event(pred, flow, source=source)
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

        query = (
            select(PacketEvent)
            .where(PacketEvent.user_id == self.user_id)
            .order_by(PacketEvent.timestamp.desc())
        )
        count_query = (
            select(func.count())
            .select_from(PacketEvent)
            .where(PacketEvent.user_id == self.user_id)
        )

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
        query = (
            select(PacketEvent)
            .where(PacketEvent.user_id == self.user_id)
            .order_by(PacketEvent.timestamp.desc())
        )

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
            user_id=self.user_id,
            src_ip=flow.src_ip if flow else None,
            dst_ip=flow.dst_ip if flow else None,
            dst_port=flow.dst_port if flow else None,
            protocol=flow.protocol if flow else None,
            prediction=prediction.prediction,
            confidence=prediction.rf_confidence,
            prob_normal=prediction.prob_normal,
            prob_suspicious=prediction.prob_suspicious,
            prob_malicious=prediction.prob_malicious,
            feature_coverage=prediction.feature_coverage,
            missing_feature_count=prediction.missing_feature_count,
            traffic_schema=prediction.traffic_schema,
            threat_score_contribution=prediction.risk_score,
            source=source,
        )
        self.db.add(event)
        # Flush so the ID is populated without committing the transaction.
        # The router's get_db() dependency commits after the handler returns.
        await self.db.flush()
        await self.db.refresh(event)
        return event.id

    async def _latest_firewall_signal(self, src_ip: str | None) -> dict[str, float]:
        if not src_ip:
            return {"score": 0.0}
        query = (
            select(FirewallAlert)
            .where(FirewallAlert.user_id == self.user_id, FirewallAlert.src_ip == src_ip)
            .order_by(FirewallAlert.timestamp.desc())
            .limit(1)
        )
        row = (await self.db.execute(query)).scalar_one_or_none()
        if row is None:
            return {"score": 0.0}
        score = float(row.anomaly_score or row.threat_score or 0.0)
        return {"score": max(0.0, min(score, 100.0))}

    async def _recent_dst_port_count(self, flow: FlowFeatures | None) -> int:
        if flow is None or not flow.src_ip:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        query = select(PacketEvent.dst_port).where(
            PacketEvent.user_id == self.user_id,
            PacketEvent.src_ip == flow.src_ip,
            PacketEvent.timestamp >= cutoff,
        )
        ports = {port for port in (await self.db.execute(query)).scalars().all() if port is not None}
        if flow.dst_port is not None:
            ports.add(flow.dst_port)
        return len(ports)

    def _build_soc_prediction(
        self,
        *,
        rf_row: pd.Series,
        packet_row: pd.Series,
        firewall_signal: dict[str, float],
        port_count: int,
        flow: FlowFeatures | None,
        packet_detector_available: bool,
    ) -> PacketPrediction:
        rf_prediction = _parse_prediction(rf_row)
        rf_probabilities = _rf_probabilities(rf_prediction)
        packet_anomaly_score = _safe_float(packet_row.get("packet_anomaly_score")) or 0.0
        firewall_score = float(firewall_signal.get("score", 0.0) or 0.0)
        packet_anomaly_level = _anomaly_level(packet_anomaly_score)
        firewall_anomaly_level = _anomaly_level(firewall_score)

        context = SOCRuleContext(
            src_ip=flow.src_ip if flow else None,
            distinct_dst_ports_short_window=port_count,
            flow_duration=flow.flow_duration if flow else None,
            total_packets=_total_packets(flow),
            flow_packets_per_second=flow.flow_pkts_per_s if flow else None,
            syn_count=float(flow.syn_flag_count or 0.0) if flow else 0.0,
            ack_count=float(flow.ack_flag_count or 0.0) if flow else 0.0,
            rf_prediction=rf_prediction.prediction,
            rf_max_probability=rf_prediction.rf_confidence,
            rf_malicious_probability=rf_prediction.prob_malicious or 0.0,
            packet_anomaly_level=packet_anomaly_level,
            firewall_anomaly_level=firewall_anomaly_level,
        )
        rule_result = self.rule_engine.evaluate(context)
        decision = self.fusion_engine.decide(
            FusionInput(
                rf_malicious_probability=rf_prediction.prob_malicious or 0.0,
                packet_anomaly_level=packet_anomaly_level,
                packet_anomaly_score=packet_anomaly_score,
                firewall_anomaly_level=firewall_anomaly_level,
                firewall_anomaly_score=firewall_score,
                soc_rule_score=rule_result.score,
                triggered_rules=rule_result.triggered_rules,
                minimum_risk=rule_result.minimum_risk,
            )
        )

        explanation = _build_explanation(
            rf_prediction=rf_prediction,
            packet_anomaly_level=packet_anomaly_level,
            packet_anomaly_score=packet_anomaly_score,
            packet_detector_available=packet_detector_available,
            firewall_anomaly_level=firewall_anomaly_level,
            firewall_anomaly_score=firewall_score,
            rule_explanations=rule_result.explanation,
        )
        final_prediction = decision.prediction
        if rule_result.force_prediction == "Malicious":
            final_prediction = "Malicious"
        elif rule_result.force_prediction == "Suspicious" and final_prediction == "Normal":
            final_prediction = "Suspicious"

        logger.info(
            "SOC packet decision src_ip={} rf={} packet_anomaly_level={} firewall_anomaly_level={} rules={} risk={} final={}",
            flow.src_ip if flow else None,
            rf_prediction.prediction,
            packet_anomaly_level,
            firewall_anomaly_level,
            rule_result.triggered_rules,
            decision.risk_score,
            final_prediction,
        )

        return rf_prediction.model_copy(
            update={
                "prediction": final_prediction,
                "risk_score": decision.risk_score,
                "rf_prediction": rf_prediction.prediction,
                "rf_probabilities": rf_probabilities,
                "packet_anomaly_level": packet_anomaly_level,
                "packet_anomaly_score": round(packet_anomaly_score, 2),
                "firewall_anomaly_level": firewall_anomaly_level,
                "firewall_anomaly_score": round(firewall_score, 2),
                "triggered_rules": rule_result.triggered_rules,
                "final_confidence": _final_confidence(final_prediction, decision.risk_score),
                "explanation": explanation,
            }
        )


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


def _empty_packet_anomaly_df(df: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "packet_anomaly": [False] * len(df),
            "packet_anomaly_score": [0.0] * len(df),
            "packet_anomaly_raw_score": [None] * len(df),
        },
        index=df.index,
    )


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
        risk_score=score,
        rf_prediction=prediction,
        rf_confidence=round(confidence, 4),
        rf_probabilities={
            key: value
            for key, value in {
                "Normal": round(prob_normal, 4) if prob_normal is not None else None,
                "Suspicious": round(prob_suspicious, 4) if prob_suspicious is not None else None,
                "Malicious": round(prob_malicious, 4) if prob_malicious is not None else None,
            }.items()
            if value is not None
        },
        final_confidence=round(confidence, 4),
        explanation=[],
        prob_normal=round(prob_normal, 4) if prob_normal is not None else None,
        prob_suspicious=round(prob_suspicious, 4) if prob_suspicious is not None else None,
        prob_malicious=round(prob_malicious, 4) if prob_malicious is not None else None,
        feature_coverage=round(feature_coverage, 4) if feature_coverage is not None else None,
        missing_feature_count=missing_count,
        traffic_schema=traffic_schema,
    )


def _rf_probabilities(prediction: PacketPrediction) -> dict[str, float]:
    values = {
        "Normal": prediction.prob_normal,
        "Suspicious": prediction.prob_suspicious,
        "Malicious": prediction.prob_malicious,
    }
    return {key: round(float(value), 4) for key, value in values.items() if value is not None}


def _total_packets(flow: FlowFeatures | None) -> float:
    if flow is None:
        return 0.0
    return float(flow.total_fwd_packets or 0.0) + float(flow.total_bwd_packets or 0.0)


def _batch_port_counts(flows: List[FlowFeatures]) -> dict[str, int]:
    ports_by_src: dict[str, set[int]] = {}
    for flow in flows:
        if flow.src_ip and flow.dst_port is not None:
            ports_by_src.setdefault(flow.src_ip, set()).add(flow.dst_port)
    return {src_ip: len(ports) for src_ip, ports in ports_by_src.items()}


def _final_confidence(prediction: str, risk_score: float) -> float:
    """
    Convert fused SOC risk into confidence for the final decision band.

    RF confidence is kept separate; this value reflects how strongly the final
    fused score supports its chosen Normal/Suspicious/Malicious decision.
    """
    risk = max(0.0, min(float(risk_score), 100.0))
    if prediction == "Normal":
        return round((40.0 - min(risk, 40.0)) / 40.0, 4)
    if prediction == "Suspicious":
        distance_to_boundary = min(abs(risk - 40.0), abs(70.0 - risk))
        return round(max(0.5, min(1.0, 0.5 + (distance_to_boundary / 30.0))), 4)
    if prediction == "Malicious":
        return round(max(0.5, min(1.0, 0.5 + ((risk - 70.0) / 30.0) * 0.5)), 4)
    return 0.0


def _anomaly_level(score: float) -> str:
    score = max(0.0, min(float(score), 100.0))
    if score >= 70.0:
        return "Malicious"
    if score >= 40.0:
        return "Suspicious"
    return "Normal"


def _build_explanation(
    *,
    rf_prediction: PacketPrediction,
    packet_anomaly_level: str,
    packet_anomaly_score: float,
    packet_detector_available: bool,
    firewall_anomaly_level: str,
    firewall_anomaly_score: float,
    rule_explanations: list[str],
) -> list[str]:
    confidence_label = "high" if rf_prediction.rf_confidence >= 0.60 else "low"
    ml_reason = (
        "ML Reasoning: Random Forest classified the flow as "
        f"{rf_prediction.prediction} with {confidence_label} confidence."
    )

    packet_reason = _anomaly_range_reason("Packet anomaly", packet_anomaly_score, packet_anomaly_level)
    firewall_reason = _anomaly_range_reason("Firewall behavior", firewall_anomaly_score, firewall_anomaly_level)
    gray_zone_reasons: list[str] = []
    if packet_anomaly_level == "Suspicious":
        gray_zone_reasons.append("packet anomaly score")
    if firewall_anomaly_level == "Suspicious":
        gray_zone_reasons.append("firewall anomaly score")

    if gray_zone_reasons:
        anomaly_reason = (
            "Anomaly Reasoning: "
            f"{packet_reason} {firewall_reason} Gray-zone logic triggered due to borderline "
            f"{' and '.join(gray_zone_reasons)}."
        )
    elif packet_detector_available:
        anomaly_reason = f"Anomaly Reasoning: {packet_reason} {firewall_reason}"
    else:
        anomaly_reason = (
            "Anomaly Reasoning: Packet anomaly detection is unavailable. "
            f"{firewall_reason}"
        )

    if rule_explanations:
        rule_summary = "; ".join(dict.fromkeys(rule_explanations))
        soc_reason = f"SOC Reasoning: One or more SOC rules were triggered ({rule_summary})."
    else:
        soc_reason = "SOC Reasoning: No SOC rules were triggered."

    return [ml_reason, anomaly_reason, soc_reason]


def _anomaly_range_reason(label: str, score: float, level: str) -> str:
    if level == "Suspicious":
        return f"{label} score falls in Suspicious range (40-70)."
    if level == "Malicious":
        return f"{label} score falls in Malicious range (70-100)."
    return f"{label} classified as Normal."


def _build_batch_response(predictions: List[PacketPrediction]) -> PacketBatchResponse:
    """Aggregate a list of predictions into a batch response with summary counts."""
    normal = sum(1 for p in predictions if p.prediction == "Normal")
    suspicious = sum(1 for p in predictions if p.prediction == "Suspicious")
    malicious = sum(1 for p in predictions if p.prediction == "Malicious")
    insufficient = sum(1 for p in predictions if p.prediction == "Insufficient Evidence")

    scores = [p.risk_score for p in predictions]
    avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0

    return PacketBatchResponse(
        success=True,
        total_flows=len(predictions),
        results=predictions,
        normal_count=normal,
        suspicious_count=suspicious,
        malicious_count=malicious,
        insufficient_evidence_count=insufficient,
        avg_risk_score=avg_score,
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
