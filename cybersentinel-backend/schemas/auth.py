"""Pydantic schemas for JWT authentication."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator

UserRole = Literal["Administrator", "Analyst", "SeniorManagement"]


def _normalize_email(value: str) -> str:
    return value.strip().lower()


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return _normalize_email(value)


class AdminCreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: UserRole = "Analyst"

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return _normalize_email(value)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return _normalize_email(value)


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=16, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class ForgotPasswordResponse(BaseModel):
    success: bool = True
    message: str = (
        "If an account exists for that email, password reset instructions have been sent."
    )


class ValidateResetTokenResponse(BaseModel):
    success: bool = True
    valid: bool
    message: str


class ResetPasswordResponse(BaseModel):
    success: bool = True
    message: str = "Password updated successfully"


class UserListResponse(BaseModel):
    success: bool = True
    total: int
    users: list[UserResponse]


class TokenResponse(BaseModel):
    success: bool = True
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Token lifetime in seconds")
    role: UserRole
    email: str


class UserResponse(BaseModel):
    success: bool = True
    id: str
    email: str
    role: UserRole
    created_at: str


class LogoutResponse(BaseModel):
    success: bool = True
    message: str = "Logged out successfully"


class ThreatQueueRequest(BaseModel):
    ips: list[str] = Field(min_length=1, max_length=50)


class ThreatQueueResponse(BaseModel):
    success: bool = True
    queued: int
    message: str
