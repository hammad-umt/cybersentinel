"""
Threat Response Center service.

The service records every response action in an audit table. By default actions
are dry-run records. Real firewall execution can be enabled per request later,
but this implementation keeps the platform safe for development and demos.
"""

from __future__ import annotations

import platform

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from db.models import ResponseAction
from schemas.response import (
    ResponseActionOut,
    ResponseActionRequest,
    ResponseActionResponse,
    ResponseActionsResponse,
)


class ResponseService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_action(self, request: ResponseActionRequest) -> ResponseActionResponse:
        command_preview = _command_preview(request.action, request.target_ip)
        execution_enabled = request.execute and settings.RESPONSE_ACTION_EXECUTION_ENABLED

        status = "dry_run"
        message = (
            "Action recorded in dry-run mode. Set RESPONSE_ACTION_EXECUTION_ENABLED=true "
            "and send execute=true to allow OS firewall execution."
        )
        executed = False

        if execution_enabled:
            status = "recorded"
            message = "Execution hooks are intentionally audit-first in this build; action recorded."

        row = ResponseAction(
            target_ip=request.target_ip,
            action=request.action,
            status=status,
            requested_by=request.requested_by,
            reason=request.reason,
            command_preview=command_preview,
            result_message=message,
            executed=executed,
        )
        self.db.add(row)
        await self.db.flush()
        await self.db.refresh(row)
        return ResponseActionResponse(action=ResponseActionOut.model_validate(row))

    async def list_actions(self, page: int, page_size: int) -> ResponseActionsResponse:
        offset = (page - 1) * page_size
        total = (await self.db.execute(
            select(func.count()).select_from(ResponseAction)
        )).scalar_one()
        rows = (await self.db.execute(
            select(ResponseAction)
            .order_by(ResponseAction.timestamp.desc())
            .offset(offset)
            .limit(page_size)
        )).scalars().all()

        return ResponseActionsResponse(
            total=total,
            page=page,
            page_size=page_size,
            actions=[ResponseActionOut.model_validate(row) for row in rows],
        )


def _command_preview(action: str, ip: str) -> str:
    system = platform.system().lower()
    if system == "windows":
        if action == "block_ip":
            return f"netsh advfirewall firewall add rule name=CyberSentinel_Block_{ip} dir=in action=block remoteip={ip}"
        if action == "unblock_ip":
            return f"netsh advfirewall firewall delete rule name=CyberSentinel_Block_{ip}"
        if action == "remove_firewall_rule":
            return f"netsh advfirewall firewall delete rule name=<rule_name_for_{ip}>"
    else:
        if action == "block_ip":
            return f"sudo ufw deny from {ip}"
        if action == "unblock_ip":
            return f"sudo ufw delete deny from {ip}"
        if action == "remove_firewall_rule":
            return f"sudo iptables -D INPUT -s {ip} -j DROP"

    if action == "whitelist":
        return f"Record {ip} as trusted/whitelisted in CyberSentinel"
    if action == "watchlist":
        return f"Record {ip} on CyberSentinel watchlist"
    return f"Record response action {action} for {ip}"
