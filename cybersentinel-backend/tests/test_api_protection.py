"""API protection tests — strict JWT enforcement."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.helpers import assert_failure_status, assert_success


PROTECTED_GET_ROUTES = [
    "/api/v1/dashboard/summary",
    "/api/v1/threat/top",
    "/api/v1/firewall/alerts",
    "/api/v1/packet/events",
    "/api/v1/capture/interfaces",
    "/api/v1/capture/status",
    "/api/v1/response/actions",
    "/api/v1/auth/users",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", PROTECTED_GET_ROUTES)
async def test_tc_api_01_protected_route_without_auth_returns_401(client: AsyncClient, path: str):
    """TC-API-01: Protected routes must return 401 without Authorization header."""
    response = await client.get(path)
    assert_failure_status(response.status_code, 401)
    assert response.json()["success"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("path", PROTECTED_GET_ROUTES)
async def test_tc_api_02_protected_route_with_admin_jwt_returns_200(
    client: AsyncClient,
    admin_headers: dict[str, str],
    path: str,
):
    """TC-API-02: Valid admin JWT must unlock protected GET routes."""
    response = await client.get(path, headers=admin_headers)
    assert_failure_status(response.status_code, 200, f"{path}: {response.text}")
    assert_success(response.json())


@pytest.mark.asyncio
async def test_tc_api_03_invalid_bearer_token_returns_401(client: AsyncClient):
    """TC-API-03: Invalid Bearer token must return 401."""
    headers = {"Authorization": "Bearer invalid.jwt.token"}
    response = await client.get("/api/v1/dashboard/summary", headers=headers)
    assert_failure_status(response.status_code, 401)
