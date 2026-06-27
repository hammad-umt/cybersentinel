"""Per-user tenant isolation — every SOC record is scoped to one user."""

from __future__ import annotations

from fastapi import HTTPException, Request, status


def get_current_user_id(request: Request) -> str:
    """Return authenticated user id set by API auth middleware."""
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    return str(user_id)
