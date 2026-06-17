"""Shared security dependencies for CyberSentinel endpoints."""

from __future__ import annotations

from typing import Literal

from fastapi import Header, HTTPException, Request, status
from loguru import logger

from core.config import settings

Role = Literal["user"]
READ_METHODS = {"GET", "HEAD", "OPTIONS"}


def resolve_api_role(
    x_api_key: str | None,
) -> Role | None:
    if settings.API_KEY and x_api_key == settings.API_KEY:
        return "user"
    return None


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def require_role(min_role: Role):
    async def _dependency(
        request: Request,
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ) -> Role:
        if not settings.API_KEY:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API key is not configured.",
            )

        role = resolve_api_role(x_api_key)
        if role is None:
            logger.warning(
                "Unauthorized API access from {ip} {method} {path}",
                ip=_client_ip(request),
                method=request.method,
                path=request.url.path,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key. Use header: X-API-Key: your-api-key",
            )

        request.state.auth_role = role
        return role

    return _dependency


async def require_admin_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """API key guard."""
    dependency = require_role("user")
    await dependency(request, x_api_key)


def enforce_read_only_analyst(request: Request, role: Role) -> None:
    """No longer needed with single API key."""
    pass
