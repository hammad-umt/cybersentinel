"""Shared security dependencies for CyberSentinel endpoints."""

from __future__ import annotations

from typing import Literal

from fastapi import Header, HTTPException, Request, status
from loguru import logger

from core.config import settings

Role = Literal["admin", "analyst"]
READ_METHODS = {"GET", "HEAD", "OPTIONS"}


def resolve_api_role(
    x_admin_api_key: str | None,
    x_analyst_api_key: str | None,
) -> Role | None:
    if settings.ADMIN_API_KEY and x_admin_api_key == settings.ADMIN_API_KEY:
        return "admin"
    if settings.ANALYST_API_KEY and x_analyst_api_key == settings.ANALYST_API_KEY:
        return "analyst"
    return None


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def require_role(min_role: Role):
    async def _dependency(
        request: Request,
        x_admin_api_key: str | None = Header(default=None, alias="X-Admin-Api-Key"),
        x_analyst_api_key: str | None = Header(default=None, alias="X-Analyst-Api-Key"),
    ) -> Role:
        if not settings.ADMIN_API_KEY and not settings.ANALYST_API_KEY:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API keys are not configured.",
            )

        role = resolve_api_role(x_admin_api_key, x_analyst_api_key)
        if role is None:
            logger.warning(
                "Unauthorized API access from {ip} {method} {path}",
                ip=_client_ip(request),
                method=request.method,
                path=request.url.path,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key.",
            )

        if min_role == "admin" and role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required.",
            )

        enforce_read_only_analyst(request, role)
        request.state.auth_role = role
        return role

    return _dependency


async def require_admin_api_key(
    request: Request,
    x_admin_api_key: str | None = Header(default=None, alias="X-Admin-Api-Key"),
    x_analyst_api_key: str | None = Header(default=None, alias="X-Analyst-Api-Key"),
) -> None:
    """Backward-compatible admin guard."""
    dependency = require_role("admin")
    await dependency(request, x_admin_api_key, x_analyst_api_key)


def enforce_read_only_analyst(request: Request, role: Role) -> None:
    if role == "analyst" and request.method not in READ_METHODS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst API keys are read-only.",
        )
