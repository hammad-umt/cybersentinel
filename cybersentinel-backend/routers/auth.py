"""JWT authentication — login, register, user management."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.security import get_current_user_payload, require_role
from db.database import get_db
from db.models import User
from schemas.auth import (
    AdminCreateUserRequest,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LogoutResponse,
    RegisterRequest,
    ResetPasswordRequest,
    ResetPasswordResponse,
    TokenResponse,
    UserListResponse,
    UserResponse,
    ValidateResetTokenResponse,
)
from services.auth_service import (
    authenticate_user,
    clear_password_reset_token,
    create_access_token,
    create_password_reset_token,
    create_user,
    list_users,
    reset_password_with_token,
    revoke_token,
    validate_password_reset_token,
)
from services.email_service import build_password_reset_link, send_password_reset_email

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


def _user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        role=user.role,  # type: ignore[arg-type]
        created_at=user.created_at,
    )


@router.post(
    "/register",
    response_model=UserResponse,
    summary="Create a new account (public signup)",
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    if not settings.ALLOW_PUBLIC_SIGNUP:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public signup is disabled. Ask an administrator to create your account.",
        )
    try:
        user = await create_user(db, body.email, body.password, role="Analyst")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return _user_response(user)


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Login with email and receive a JWT access token",
)
async def login_for_token(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    # OAuth2 form field is named `username`; we treat it as the user's email.
    user = await authenticate_user(db, form.username, form.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, expires_in = create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role,
    )
    return TokenResponse(
        access_token=token,
        expires_in=expires_in,
        role=user.role,  # type: ignore[arg-type]
        email=user.email,
    )


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    summary="Request a password reset link by email",
)
async def forgot_password(
    body: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
) -> ForgotPasswordResponse:
    if not settings.email_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Password reset email is not configured on the server. "
                "Set RESEND_API_KEY or SMTP_* in the backend .env file."
            ),
        )

    reset_token = await create_password_reset_token(db, body.email)
    if not reset_token:
        return ForgotPasswordResponse()

    reset_link = build_password_reset_link(reset_token)
    sent = await send_password_reset_email(to_email=body.email, reset_link=reset_link)
    if not sent:
        await clear_password_reset_token(db, body.email)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to send password reset email. Please try again later.",
        )

    return ForgotPasswordResponse()


@router.get(
    "/reset-password/validate",
    response_model=ValidateResetTokenResponse,
    summary="Check whether a reset link token is still valid",
)
async def validate_reset_token(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> ValidateResetTokenResponse:
    valid = await validate_password_reset_token(db, token)
    if valid:
        return ValidateResetTokenResponse(
            valid=True,
            message="Reset link is valid. You can set a new password.",
        )
    return ValidateResetTokenResponse(
        valid=False,
        message="Reset link is invalid or has expired. Request a new one.",
    )


@router.post(
    "/reset-password",
    response_model=ResetPasswordResponse,
    summary="Set a new password using a reset token",
)
async def reset_password(
    body: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
) -> ResetPasswordResponse:
    updated = await reset_password_with_token(db, body.token, body.new_password)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )
    return ResetPasswordResponse()


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get the currently authenticated user",
)
async def read_current_user(
    payload: dict = Depends(get_current_user_payload),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    from sqlalchemy import select

    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return _user_response(user)


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List all users (admin only)",
    dependencies=[Depends(require_role("admin"))],
)
async def get_users(db: AsyncSession = Depends(get_db)) -> UserListResponse:
    users = await list_users(db)
    return UserListResponse(
        total=len(users),
        users=[_user_response(u) for u in users],
    )


@router.post(
    "/users",
    response_model=UserResponse,
    summary="Create a user with any role (admin only)",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role("admin"))],
)
async def admin_create_user(
    body: AdminCreateUserRequest,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    try:
        user = await create_user(db, body.email, body.password, role=body.role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return _user_response(user)


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Invalidate the current JWT (server-side revoke)",
)
async def logout(
    authorization: str | None = Header(default=None),
) -> LogoutResponse:
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        revoke_token(token)
    return LogoutResponse()
