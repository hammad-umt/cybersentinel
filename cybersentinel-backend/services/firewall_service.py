"""
services/firewall_service.py

Business logic for the unsupervised firewall log analysis module.

Responsibilities:
  1. Parse uploaded log files using your windows_log_reader
  2. Call UnsupervisedPipeline.predict() or ingest_realtime()
  3. Convert raw pipeline output into clean response schemas
  4. Persist threat signals to the firewall_alerts DB table
  5. Handle alert acknowledgement
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List

import pandas as pd
from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from db.models import FirewallAlert
from models.loader import ModelRegistry
from schemas.firewall import (
    AckResponse,
    AnomalyRow,
    ClusterRow,
    FirewallAlertOut,
    FirewallAlertsResponse,
    FirewallAnalyzeResponse,
    FirewallIngestResponse,
    ThreatSignal,
    ValidationReport,
)


class FirewallService:
    """
    Wraps UnsupervisedPipeline for use in FastAPI route handlers.

    Usage:
        service = FirewallService(registry=request.app.state.models, db=db)
        response = await service.analyze_file(file_bytes, filename)
    """

    def __init__(self, registry: ModelRegistry, db: AsyncSession):
        self.registry = registry
        self.db = db

    # ------------------------------------------------------------------
    # Public API — called by routers
    # ------------------------------------------------------------------

    async def analyze_file(
        self,
        file_bytes: bytes,
        filename: str,
        source: str = "auto",
    ) -> FirewallAnalyzeResponse:
        """
        Parse an uploaded firewall log file and run the full pipeline.
        Supports Windows pfirewall.log and Linux iptables/UFW logs.
        """
        pipeline = self.registry.require_firewall_pipeline()

        # Detect log source from filename if auto
        detected_source = _detect_source(filename, source)
        logger.info(
            "Analyzing firewall log: filename={} source={} size={} bytes",
            filename, detected_source, len(file_bytes),
        )

        # Parse the log file into a DataFrame
        df = _parse_log_bytes(file_bytes, filename, detected_source)
        logger.info("Parsed {} log rows from {}", len(df), filename)

        # Run the unsupervised pipeline
        results = pipeline.predict(df)

        # Build the response
        session_id = str(uuid.uuid4())[:8]
        return await self._build_analyze_response(
            results=results,
            log_source=detected_source,
            session_id=session_id,
        )

    async def ingest_realtime(
        self, event: Dict[str, Any]
    ) -> FirewallIngestResponse:
        """
        Ingest one live firewall event into the rolling buffer and score.
        Called when Flutter sends a single event from a live log tail.
        """
        pipeline = self.registry.require_firewall_pipeline()

        logger.debug("Ingesting realtime event: {}", event)
        results = pipeline.ingest_realtime(event)

        signals = _parse_signals(results.get("threat_signals", []))
        saved_signals = await self._save_signals(signals, source_session="realtime")

        return FirewallIngestResponse(
            success=True,
            buffered_events=int(results.get("buffered_events", 0)),
            scored_events=int(results.get("scored_events", 0)),
            threat_signals=saved_signals,
            alert_triggered=any(
                s.severity in ("Suspicious", "Malicious-like", "Critical")
                for s in saved_signals
            ),
        )

    async def get_alerts(
        self,
        page: int = 1,
        page_size: int = 50,
        severity_filter: str | None = None,
        unacknowledged_only: bool = False,
    ) -> FirewallAlertsResponse:
        """
        Return paginated firewall alerts from DB.
        Flutter uses this for the alerts list and the dashboard summary.
        """
        page_size = min(page_size, settings.MAX_PAGE_SIZE)
        offset = (page - 1) * page_size

        query = select(FirewallAlert).order_by(FirewallAlert.threat_score.desc())
        count_query = select(func.count()).select_from(FirewallAlert)
        unack_query = select(func.count()).select_from(FirewallAlert).where(
            FirewallAlert.acknowledged == False  # noqa: E712
        )

        if severity_filter:
            query = query.where(FirewallAlert.severity == severity_filter)
            count_query = count_query.where(FirewallAlert.severity == severity_filter)

        if unacknowledged_only:
            query = query.where(FirewallAlert.acknowledged == False)  # noqa: E712
            count_query = count_query.where(FirewallAlert.acknowledged == False)  # noqa: E712

        total = (await self.db.execute(count_query)).scalar_one()
        unack_count = (await self.db.execute(unack_query)).scalar_one()
        rows = (await self.db.execute(query.offset(offset).limit(page_size))).scalars().all()

        return FirewallAlertsResponse(
            success=True,
            total=total,
            page=page,
            page_size=page_size,
            unacknowledged_count=unack_count,
            alerts=[FirewallAlertOut.model_validate(row) for row in rows],
        )

    async def acknowledge_alert(self, alert_id: str) -> AckResponse:
        """Mark one alert as acknowledged by the admin in Flutter."""
        result = await self.db.execute(
            select(FirewallAlert).where(FirewallAlert.id == alert_id)
        )
        alert = result.scalar_one_or_none()
        if alert is None:
            raise ValueError(f"Alert {alert_id} not found")

        alert.acknowledged = True
        await self.db.flush()
        logger.info("Alert {} acknowledged", alert_id)
        return AckResponse(success=True, alert_id=alert_id, acknowledged=True)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _build_analyze_response(
        self,
        results: dict,
        log_source: str,
        session_id: str,
    ) -> FirewallAnalyzeResponse:
        """Convert raw pipeline output dict into a FirewallAnalyzeResponse."""

        validation = _parse_validation(results.get("validation_report", {}))
        signals = _parse_signals(results.get("threat_signals", []))
        saved_signals = await self._save_signals(signals, source_session=session_id)

        anomaly_df: pd.DataFrame = results.get("anomaly_df", pd.DataFrame())
        cluster_df: pd.DataFrame = results.get("cluster_df", pd.DataFrame())

        anomaly_rows = _df_to_anomaly_rows(anomaly_df)
        cluster_rows = _df_to_cluster_rows(cluster_df)

        # Summary counts from threat signals
        severity_counts = _count_severities(saved_signals)

        return FirewallAnalyzeResponse(
            success=True,
            validation_report=validation,
            threat_signals=saved_signals,
            anomaly_results=anomaly_rows,
            cluster_results=cluster_rows,
            total_ips_analyzed=len(cluster_df) if not cluster_df.empty else 0,
            suspicious_ips=severity_counts["Suspicious"],
            malicious_ips=severity_counts["Malicious-like"],
            critical_ips=severity_counts["Critical"],
            max_threat_score=max((s.threat_score for s in saved_signals), default=0.0),
            log_source=log_source,
        )

    async def _save_signals(
        self,
        signals: List[ThreatSignal],
        source_session: str = "",
    ) -> List[ThreatSignal]:
        """
        Persist threat signals to firewall_alerts table.
        Attaches the generated alert_id back to each ThreatSignal so
        Flutter can reference the DB record.
        """
        saved = []
        for signal in signals:
            alert = FirewallAlert(
                src_ip=signal.src_ip,
                threat_score=signal.threat_score,
                anomaly_score=signal.anomaly_score,
                heuristic_score=signal.heuristic_score,
                severity=signal.severity,
                cluster_label=signal.cluster_label,
                attack_signals=signal.attack_signals,
                consensus_anomaly=signal.consensus_anomaly,
                evidence_json=json.dumps(signal.evidence),
                acknowledged=False,
                source_session=source_session,
            )
            self.db.add(alert)
            await self.db.flush()
            await self.db.refresh(alert)

            # Attach the DB ID to the signal for the response
            signal_with_id = signal.model_copy(update={"alert_id": alert.id})
            saved.append(signal_with_id)

        return saved


# ---------------------------------------------------------------------------
# Pure helper functions
# ---------------------------------------------------------------------------

def _detect_source(filename: str, hint: str) -> str:
    """Detect log format from filename if hint is 'auto'."""
    if hint != "auto":
        return hint
    name_lower = filename.lower()
    if "pfirewall" in name_lower or "windows" in name_lower:
        return "windows"
    if any(k in name_lower for k in ("ufw", "iptables", "kern", "syslog")):
        return "iptables"
    return "auto"


def _parse_log_bytes(file_bytes: bytes, filename: str, source: str) -> pd.DataFrame:
    """
    Route the uploaded file to the correct parser.
    Imports windows_log_reader from your existing unsupervised_learning folder.
    """
    import sys
    from pathlib import Path

    # Ensure unsupervised_learning is importable
    ul_path = str((Path(__file__).resolve().parent.parent.parent / "unsupervised_learning"))
    if ul_path not in sys.path:
        sys.path.insert(0, ul_path)

    from windows_log_reader import read_firewall_log

    # Write bytes to a temp-like in-memory path using a temp file
    import os
    import tempfile
    suffix = Path(filename).suffix or ".log"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        df = read_firewall_log(tmp_path, source=source)
    finally:
        os.unlink(tmp_path)

    return df


def _parse_validation(raw: dict) -> ValidationReport:
    return ValidationReport(
        input_rows=int(raw.get("input_rows", 0)),
        valid_rows=int(raw.get("valid_rows", 0)),
        dropped_rows=int(raw.get("dropped_rows", 0)),
        duplicates_removed=int(raw.get("duplicates_removed", 0)),
        warnings=raw.get("warnings", []),
    )


def _parse_signals(raw_signals: list[dict]) -> List[ThreatSignal]:
    """Convert raw ThreatSignalEmitter dicts into ThreatSignal Pydantic objects."""
    signals = []
    for raw in raw_signals:
        try:
            signals.append(ThreatSignal(**raw))
        except Exception as exc:
            logger.warning("Skipping malformed threat signal: {} — {}", raw, exc)
    return signals


def _df_to_anomaly_rows(df: pd.DataFrame) -> List[AnomalyRow]:
    if df.empty:
        return []
    rows = []
    for _, row in df.iterrows():
        try:
            rows.append(AnomalyRow(
                src_ip=str(row["src_ip"]),
                hour_window=str(row["hour_window"]),
                anomaly_score=float(row["anomaly_score"]),
                severity=str(row["severity"]),
                consensus_anomaly=bool(row["consensus_anomaly"]),
                failed_attempts=float(row.get("failed_attempts", 0)),
            ))
        except Exception as exc:
            logger.warning("Skipping malformed anomaly row: {}", exc)
    return rows


def _df_to_cluster_rows(df: pd.DataFrame) -> List[ClusterRow]:
    if df.empty:
        return []
    rows = []
    for _, row in df.iterrows():
        try:
            rows.append(ClusterRow(
                src_ip=str(row["src_ip"]),
                total_events=int(row.get("total_events", 0)),
                block_ratio=float(row.get("block_ratio", 0.0)),
                unique_ports=int(row.get("unique_ports", 0)),
                cluster_interpretation=str(row.get("cluster_interpretation", "Normal")),
                attack_signal_count=int(row.get("attack_signal_count", 0)),
                distance_outlier=bool(row.get("distance_outlier", False)),
            ))
        except Exception as exc:
            logger.warning("Skipping malformed cluster row: {}", exc)
    return rows


def _count_severities(signals: List[ThreatSignal]) -> dict[str, int]:
    counts: dict[str, int] = {"Suspicious": 0, "Malicious-like": 0, "Critical": 0}
    for s in signals:
        if s.severity in counts:
            counts[s.severity] += 1
    return counts
