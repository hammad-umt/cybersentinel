"""Remote monitoring agent registration and telemetry ingestion."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AgentTelemetry, MonitoringAgent
from schemas.agent import (
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentStatusOut,
    AgentStatusResponse,
    AgentTelemetryRequest,
    AgentTelemetryResponse,
)
from schemas.packet import FlowFeatureVector, FlowInput, PacketClassifyRequest
from services.firewall_service import FirewallService
from services.packet_service import PacketService


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentService:
    def __init__(self, db: AsyncSession, user_id: str, registry, packet_service_factory=None):
        self.db = db
        self.user_id = user_id
        self.registry = registry
        self._packet_service_factory = packet_service_factory

    async def register(self, body: AgentRegisterRequest) -> AgentRegisterResponse:
        existing = (
            await self.db.execute(
                select(MonitoringAgent).where(
                    MonitoringAgent.user_id == self.user_id,
                    MonitoringAgent.agent_id == body.agent_id,
                )
            )
        ).scalar_one_or_none()

        api_key = secrets.token_urlsafe(32)
        key_hash = _hash_key(api_key)

        if existing:
            existing.hostname = body.hostname
            existing.api_key_hash = key_hash
            existing.status = "active"
            existing.last_seen = _now()
            existing.metadata_json = json.dumps(body.metadata, default=str)
        else:
            self.db.add(
                MonitoringAgent(
                    user_id=self.user_id,
                    agent_id=body.agent_id,
                    hostname=body.hostname,
                    api_key_hash=key_hash,
                    status="active",
                    last_seen=_now(),
                    metadata_json=json.dumps(body.metadata, default=str),
                )
            )
        await self.db.flush()
        return AgentRegisterResponse(agent_id=body.agent_id, api_key=api_key)

    async def verify_agent(self, agent_id: str, api_key: str) -> MonitoringAgent | None:
        row = (
            await self.db.execute(
                select(MonitoringAgent).where(
                    MonitoringAgent.user_id == self.user_id,
                    MonitoringAgent.agent_id == agent_id,
                )
            )
        ).scalar_one_or_none()
        if not row or row.api_key_hash != _hash_key(api_key):
            return None
        return row

    async def ingest_telemetry(
        self,
        body: AgentTelemetryRequest,
        *,
        agent_row: MonitoringAgent,
    ) -> AgentTelemetryResponse:
        agent_row.last_seen = _now()
        agent_row.status = "active"
        packets_processed = 0
        firewall_processed = 0

        if body.packet_data:
            self.db.add(
                AgentTelemetry(
                    user_id=self.user_id,
                    agent_id=body.agent_id,
                    telemetry_type="packet",
                    payload_json=json.dumps(body.packet_data, default=str),
                    processed=False,
                )
            )
            try:
                await self._process_packet(body.packet_data)
                packets_processed = 1
            except Exception as exc:
                logger.warning("Agent packet processing failed: {}", exc)

        for log_event in body.firewall_logs:
            self.db.add(
                AgentTelemetry(
                    user_id=self.user_id,
                    agent_id=body.agent_id,
                    telemetry_type="firewall",
                    payload_json=json.dumps(log_event, default=str),
                    processed=True,
                )
            )
            try:
                fw = FirewallService(self.registry, self.db, self.user_id)
                await fw.ingest_realtime(log_event)
                firewall_processed += 1
            except Exception as exc:
                logger.warning("Agent firewall ingest failed: {}", exc)

        await self.db.flush()
        return AgentTelemetryResponse(
            agent_id=body.agent_id,
            packets_processed=packets_processed,
            firewall_events_processed=firewall_processed,
        )

    async def _process_packet(self, packet_data: dict) -> None:
        features_raw = packet_data.get("features") or packet_data
        source_ip = packet_data.get("source_ip") or packet_data.get("src_ip")
        dest_ip = packet_data.get("dest_ip") or packet_data.get("dst_ip")
        dest_port = packet_data.get("dest_port") or packet_data.get("dst_port")
        protocol = packet_data.get("protocol", "TCP")

        if isinstance(features_raw, dict) and features_raw:
            flow = FlowInput(
                features=FlowFeatureVector.model_validate(features_raw),
                source_ip=source_ip,
                dest_ip=dest_ip,
                dest_port=dest_port,
                protocol=protocol,
            )
        else:
            req = PacketClassifyRequest.model_validate(packet_data)
            flow = req.to_flow_input()

        svc = PacketService(self.registry, self.db, self.user_id)
        await svc.classify_single(flow)

    async def list_status(self) -> AgentStatusResponse:
        rows = (
            await self.db.execute(
                select(MonitoringAgent)
                .where(MonitoringAgent.user_id == self.user_id)
                .order_by(MonitoringAgent.last_seen.desc())
            )
        ).scalars().all()
        now = datetime.now(timezone.utc)
        agents: list[AgentStatusOut] = []
        for row in rows:
            status = row.status
            if row.last_seen:
                try:
                    seen = datetime.fromisoformat(row.last_seen)
                    if seen.tzinfo is None:
                        seen = seen.replace(tzinfo=timezone.utc)
                    if (now - seen).total_seconds() > 300:
                        status = "offline"
                except ValueError:
                    pass
            agents.append(
                AgentStatusOut(
                    agent_id=row.agent_id,
                    hostname=row.hostname,
                    status=status,  # type: ignore[arg-type]
                    last_seen=row.last_seen,
                    registered_at=row.registered_at,
                )
            )
        return AgentStatusResponse(agents=agents)
