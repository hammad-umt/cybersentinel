"""Role-based access control tests — strict pass/fail assertions."""

from __future__ import annotations

import io

import pytest
from httpx import AsyncClient

from tests.helpers import assert_failure_status, assert_success


@pytest.mark.asyncio
async def test_tc_rbac_01_analyst_cannot_list_users(client: AsyncClient, analyst_headers: dict[str, str]):
    """TC-RBAC-01: GET /auth/users as Analyst must return HTTP 403."""
    response = await client.get("/api/v1/auth/users", headers=analyst_headers)
    assert_failure_status(response.status_code, 403)


@pytest.mark.asyncio
async def test_tc_rbac_02_admin_can_list_users(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-RBAC-02: Admin list users must return HTTP 200."""
    response = await client.get("/api/v1/auth/users", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert body["total"] >= 1


@pytest.mark.asyncio
async def test_tc_rbac_03_analyst_cannot_create_users(client: AsyncClient, analyst_headers: dict[str, str]):
    """TC-RBAC-03: POST /auth/users as Analyst must return HTTP 403."""
    response = await client.post(
        "/api/v1/auth/users",
        headers=analyst_headers,
        json={"email": "blocked@example.com", "password": "securepass123", "role": "Analyst"},
    )
    assert_failure_status(response.status_code, 403)


@pytest.mark.asyncio
async def test_tc_rbac_04_admin_creates_manager(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-RBAC-04: Admin create SeniorManagement must return HTTP 201."""
    response = await client.post(
        "/api/v1/auth/users",
        headers=admin_headers,
        json={
            "email": "rbacmanager@example.com",
            "password": "securepass123",
            "role": "SeniorManagement",
        },
    )
    assert_failure_status(response.status_code, 201)
    assert response.json()["role"] == "SeniorManagement"


@pytest.mark.asyncio
async def test_tc_rbac_05_manager_reads_dashboard(client: AsyncClient, manager_headers: dict[str, str]):
    """TC-RBAC-05: Manager JWT must access dashboard."""
    response = await client.get("/api/v1/dashboard/summary", headers=manager_headers)
    assert_failure_status(response.status_code, 200)
    assert_success(response.json())


@pytest.mark.asyncio
async def test_tc_rbac_06_analyst_reads_threats(client: AsyncClient, analyst_headers: dict[str, str]):
    """TC-RBAC-06: Analyst JWT must access threat top list."""
    response = await client.get("/api/v1/threat/top", headers=analyst_headers)
    assert_failure_status(response.status_code, 200)


@pytest.mark.asyncio
async def test_tc_rbac_07_analyst_cannot_import_pcap(client: AsyncClient, analyst_headers: dict[str, str]):
    """TC-RBAC-07: Analyst PCAP import must return HTTP 403."""
    response = await client.post(
        "/api/v1/capture/import",
        headers=analyst_headers,
        files={"file": ("x.pcap", io.BytesIO(b"data"), "application/octet-stream")},
    )
    assert_failure_status(response.status_code, 403)
