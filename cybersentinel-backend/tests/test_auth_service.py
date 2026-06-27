"""Unit tests for services/auth_service.py."""

from __future__ import annotations

import pytest

from db.database import AsyncSessionLocal
from services.auth_service import (
    authenticate_user,
    create_access_token,
    create_password_reset_token,
    create_user,
    decode_access_token,
    hash_password,
    reset_password_with_token,
    revoke_token,
    validate_password_reset_token,
    verify_password,
)


def test_tc_unit_auth_01_password_hash_roundtrip():
    """TC-UNIT-AUTH-01: bcrypt must verify only the correct password."""
    hashed = hash_password("secretpass123")
    assert verify_password("secretpass123", hashed) is True
    assert verify_password("wrongpass", hashed) is False


def test_tc_unit_auth_02_jwt_create_and_decode():
    """TC-UNIT-AUTH-02: JWT must encode and decode user claims."""
    token, expires_in = create_access_token(
        user_id="user-1",
        email="user@example.com",
        role="Analyst",
    )
    assert expires_in == 3600
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "user-1"
    assert payload["email"] == "user@example.com"
    assert payload["role"] == "Analyst"


def test_tc_unit_auth_03_jwt_revoke():
    """TC-UNIT-AUTH-03: Revoked JWT must not decode."""
    token, _ = create_access_token(user_id="u2", email="u2@example.com", role="Analyst")
    assert decode_access_token(token) is not None
    assert revoke_token(token) is True
    assert decode_access_token(token) is None


@pytest.mark.asyncio
async def test_tc_unit_auth_04_create_and_authenticate_user(db_tables):
    """TC-UNIT-AUTH-04: Created user must authenticate with correct password."""
    async with AsyncSessionLocal() as db:
        user = await create_user(db, "unit@example.com", "password12345", role="Analyst")
        assert user.email == "unit@example.com"
        assert await authenticate_user(db, "unit@example.com", "password12345") is not None
        assert await authenticate_user(db, "unit@example.com", "wrong") is None


@pytest.mark.asyncio
async def test_tc_unit_auth_05_password_reset_token_lifecycle(db_tables):
    """TC-UNIT-AUTH-05: Reset token works once, then expires after use."""
    async with AsyncSessionLocal() as db:
        await create_user(db, "reset@example.com", "oldpass12345", role="Analyst")
        token = await create_password_reset_token(db, "reset@example.com")
        assert token is not None
        assert await validate_password_reset_token(db, token) is True
        assert await reset_password_with_token(db, token, "newpass12345") is True
        assert await validate_password_reset_token(db, token) is False
        assert await authenticate_user(db, "reset@example.com", "newpass12345") is not None
