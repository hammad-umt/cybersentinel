"""Authentication API tests — strict pass/fail assertions."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from db.database import AsyncSessionLocal
from services.auth_service import create_password_reset_token
from tests.helpers import assert_failure_status, assert_success

ADMIN_EMAIL = "admin@cybersentinel.local"
ADMIN_PASSWORD = "admin123"


@pytest.mark.asyncio
async def test_tc_auth_01_login_valid_credentials(client: AsyncClient):
    """TC-AUTH-01: Valid credentials must return HTTP 200 and bearer token."""
    response = await client.post(
        "/api/v1/auth/token",
        data={"username": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert body["token_type"] == "bearer"
    assert body["email"] == ADMIN_EMAIL
    assert body["role"] == "Administrator"
    assert len(body["access_token"]) > 20


@pytest.mark.asyncio
async def test_tc_auth_02_login_invalid_password(client: AsyncClient):
    """TC-AUTH-02: Wrong password must return HTTP 401."""
    response = await client.post(
        "/api/v1/auth/token",
        data={"username": ADMIN_EMAIL, "password": "wrong-password"},
    )
    assert_failure_status(response.status_code, 401)
    assert response.json()["success"] is False


@pytest.mark.asyncio
async def test_tc_auth_03_register_creates_analyst(client: AsyncClient):
    """TC-AUTH-03: Registration must return HTTP 201 with Analyst role."""
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "newanalyst@example.com", "password": "securepass123"},
    )
    assert_failure_status(response.status_code, 201)
    body = response.json()
    assert_success(body)
    assert body["email"] == "newanalyst@example.com"
    assert body["role"] == "Analyst"


@pytest.mark.asyncio
async def test_tc_auth_04_register_duplicate_email(client: AsyncClient):
    """TC-AUTH-04: Duplicate email must return HTTP 400."""
    payload = {"email": "duplicate@example.com", "password": "securepass123"}
    assert_failure_status((await client.post("/api/v1/auth/register", json=payload)).status_code, 201)
    response = await client.post("/api/v1/auth/register", json=payload)
    assert_failure_status(response.status_code, 400)


@pytest.mark.asyncio
async def test_tc_auth_05_me_with_valid_token(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-AUTH-05: GET /auth/me with JWT must return HTTP 200."""
    response = await client.get("/api/v1/auth/me", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert body["email"] == ADMIN_EMAIL


@pytest.mark.asyncio
async def test_tc_auth_06_me_without_token(client: AsyncClient):
    """TC-AUTH-06: GET /auth/me without JWT must return HTTP 401."""
    response = await client.get("/api/v1/auth/me")
    assert_failure_status(response.status_code, 401)


@pytest.mark.asyncio
async def test_tc_auth_07_logout_revokes_token(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-AUTH-07: Logout must invalidate the JWT."""
    assert_failure_status((await client.post("/api/v1/auth/logout", headers=admin_headers)).status_code, 200)
    response = await client.get("/api/v1/auth/me", headers=admin_headers)
    assert_failure_status(response.status_code, 401)


@pytest.mark.asyncio
async def test_tc_auth_08_password_reset_flow(client: AsyncClient):
    """TC-AUTH-08: Valid reset token must allow password change."""
    email = "resetflow@example.com"
    assert_failure_status(
        (await client.post("/api/v1/auth/register", json={"email": email, "password": "oldpassword123"})).status_code,
        201,
    )
    async with AsyncSessionLocal() as db:
        token = await create_password_reset_token(db, email)
    assert token is not None

    validate = await client.get(f"/api/v1/auth/reset-password/validate?token={token}")
    assert_failure_status(validate.status_code, 200)
    assert validate.json()["valid"] is True

    reset = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": "newpassword123"},
    )
    assert_failure_status(reset.status_code, 200)

    old_login = await client.post(
        "/api/v1/auth/token",
        data={"username": email, "password": "oldpassword123"},
    )
    assert_failure_status(old_login.status_code, 401)

    new_login = await client.post(
        "/api/v1/auth/token",
        data={"username": email, "password": "newpassword123"},
    )
    assert_failure_status(new_login.status_code, 200)


@pytest.mark.asyncio
async def test_tc_auth_09_invalid_reset_token(client: AsyncClient):
    """TC-AUTH-09: Invalid reset token must fail validation and reset."""
    validate = await client.get("/api/v1/auth/reset-password/validate?token=invalid-token-value")
    assert_failure_status(validate.status_code, 200)
    assert validate.json()["valid"] is False

    reset = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": "invalid-token-value", "new_password": "newpassword123"},
    )
    assert_failure_status(reset.status_code, 400)


@pytest.mark.asyncio
async def test_tc_auth_10_forgot_password_without_email_service(client: AsyncClient):
    """TC-AUTH-10: Forgot-password without SMTP/Resend must return HTTP 503."""
    email = "forgot@example.com"
    assert_failure_status(
        (await client.post("/api/v1/auth/register", json={"email": email, "password": "securepass123"})).status_code,
        201,
    )
    response = await client.post("/api/v1/auth/forgot-password", json={"email": email})
    assert_failure_status(response.status_code, 503)
