"""System and OpenAPI tests — strict pass/fail assertions."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.helpers import assert_failure_status, assert_success


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/", "/health"])
async def test_tc_sys_01_public_routes(client: AsyncClient, path: str):
    """TC-SYS-01: Public routes must return HTTP 200 without auth."""
    response = await client.get(path)
    assert_failure_status(response.status_code, 200)
    assert_success(response.json())


@pytest.mark.asyncio
async def test_tc_sys_02_health_reports_jwt_mode(client: AsyncClient):
    """TC-SYS-02: Health must report jwt auth and database status."""
    response = await client.get("/health")
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert body["auth"] == "jwt"
    assert body["database"] == "ok"


@pytest.mark.asyncio
async def test_tc_sys_03_openapi_bearer_scheme(client: AsyncClient):
    """TC-SYS-03: OpenAPI must expose BearerAuth for Swagger Authorize."""
    response = await client.get("/openapi.json")
    assert_failure_status(response.status_code, 200)
    schema = response.json()
    assert schema["components"]["securitySchemes"]["BearerAuth"]["scheme"] == "bearer"
    assert schema["paths"]["/api/v1/dashboard/summary"]["get"]["security"] == [{"BearerAuth": []}]
    assert schema["paths"]["/api/v1/auth/token"]["post"]["security"] == []
