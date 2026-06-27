"""Shared security dependencies for CyberSentinel endpoints."""

from __future__ import annotations

from typing import Literal

from fastapi import Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from loguru import logger

from core.config import settings
from services.auth_service import decode_access_token

Role = Literal["admin", "analyst", "manager", "user"]

READ_METHODS = {"GET", "HEAD", "OPTIONS"}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)

# Maps JWT/database role names to internal auth roles.
_JWT_ROLE_MAP: dict[str, Role] = {
    "Administrator": "admin",
    "Analyst": "analyst",
    "SeniorManagement": "manager",
}

_ROLE_RANK: dict[Role, int] = {
    "user": 1,
    "analyst": 2,
    "manager": 3,
    "admin": 4,
}


def resolve_api_role(x_api_key: str | None) -> Role | None:
    if settings.API_KEY and x_api_key == settings.API_KEY:
        return "admin"
    return None


def resolve_bearer_role(authorization: str | None) -> Role | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_access_token(token)
    if not payload:
        return None
    jwt_role = payload.get("role", "Analyst")
    return _JWT_ROLE_MAP.get(str(jwt_role), "analyst")


def resolve_request_role(
    x_api_key: str | None,
    authorization: str | None,
) -> Role | None:
    """JWT is the primary auth method. API key is optional legacy fallback."""
    bearer_role = resolve_bearer_role(authorization)
    if bearer_role is not None:
        return bearer_role
    if settings.USE_API_KEY_AUTH:
        return resolve_api_role(x_api_key)
    return None


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _role_meets_minimum(actual: Role, minimum: Role) -> bool:
    return _ROLE_RANK[actual] >= _ROLE_RANK[minimum]


def require_role(min_role: Role):
    async def _dependency(request: Request) -> Role:
        role: Role | None = getattr(request.state, "auth_role", None)
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Login via POST /api/v1/auth/token and send Authorization: Bearer <token>.",
            )
        if not _role_meets_minimum(role, min_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Requires {min_role} role.",
            )
        return role

    return _dependency


async def require_admin_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    dependency = require_role("admin")
    await dependency(request)


def enforce_read_only_analyst(request: Request, role: Role) -> None:
    if role == "analyst" and request.method not in READ_METHODS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst role is read-only for this endpoint.",
        )


async def get_current_user_payload(
    authorization: str | None = Header(default=None),
) -> dict:
    role = resolve_bearer_role(authorization)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
        )
    token = authorization.split(" ", 1)[1].strip()  # type: ignore[union-attr]
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token.")
    return payload
