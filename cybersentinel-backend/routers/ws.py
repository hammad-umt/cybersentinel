"""WebSocket routes for live alert streaming."""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.security import decode_access_token
from services.alert_broadcast import alert_hub

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket) -> None:
    """
    Live alert stream for authenticated users.

  Connect with: ws://host/ws/alerts?token=<JWT>
    """
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4401)
        return
    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        await websocket.close(code=4401)
        return

    user_id = str(payload["sub"])
    await alert_hub.connect(user_id, websocket)
    try:
        while True:
            # Keep connection alive; clients may send ping messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await alert_hub.disconnect(user_id, websocket)
