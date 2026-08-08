"""
WebSocket alert broadcast hub for live dashboard updates.

Pushes threat alerts, critical events, and incident updates to connected clients.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket
from loguru import logger


class AlertBroadcastHub:
    """In-process pub/sub for WebSocket alert streaming."""

    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, user_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.setdefault(user_id, set()).add(websocket)
        logger.debug("WebSocket connected for user {}", user_id)

    async def disconnect(self, user_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            bucket = self._connections.get(user_id)
            if bucket and websocket in bucket:
                bucket.discard(websocket)
            if bucket is not None and not bucket:
                self._connections.pop(user_id, None)

    async def publish(self, user_id: str, event_type: str, payload: dict[str, Any]) -> None:
        message = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        raw = json.dumps(message, default=str)
        async with self._lock:
            sockets = list(self._connections.get(user_id, set()))
        dead: list[WebSocket] = []
        for ws in sockets:
            try:
                await ws.send_text(raw)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(user_id, ws)

    async def publish_threat(self, user_id: str, payload: dict[str, Any]) -> None:
        await self.publish(user_id, "threat", payload)

    async def publish_critical_alert(self, user_id: str, payload: dict[str, Any]) -> None:
        await self.publish(user_id, "critical_alert", payload)

    async def publish_incident(self, user_id: str, payload: dict[str, Any]) -> None:
        await self.publish(user_id, "incident_update", payload)


# Singleton used across the application
alert_hub = AlertBroadcastHub()
