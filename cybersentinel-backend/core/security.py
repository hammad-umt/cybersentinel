"""Shared security dependencies for privileged CyberSentinel endpoints."""

from __future__ import annotations

from fastapi import Header, HTTPException, status

from core.config import settings


async def require_admin_api_key(
    x_admin_api_key: str | None = Header(default=None),
) -> None:
    """Require a configured and matching X-Admin-Api-Key header."""
    if not settings.ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API key is not configured.",
        )
    if x_admin_api_key != settings.ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin API key.",
        )
