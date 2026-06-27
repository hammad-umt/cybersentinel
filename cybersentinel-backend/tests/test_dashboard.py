"""Dashboard API tests — strict pass/fail assertions."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.helpers import assert_failure_status, assert_success


@pytest.mark.asyncio
async def test_tc_dash_01_summary_requires_authentication(client: AsyncClient):
    """TC-DASH-01: Dashboard summary without JWT must return 401."""
    response = await client.get("/api/v1/dashboard/summary")
    assert_failure_status(response.status_code, 401)


@pytest.mark.asyncio
async def test_tc_dash_02_summary_returns_kpis(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-DASH-02: Dashboard summary must return KPI fields."""
    response = await client.get("/api/v1/dashboard/summary", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert isinstance(body["packet_events"], int)
    assert isinstance(body["firewall_alerts"], int)
    assert isinstance(body["severity_distribution"], list)
    assert isinstance(body["trend"], list)


@pytest.mark.asyncio
async def test_tc_dash_03_analyst_can_read_summary(client: AsyncClient, analyst_headers: dict[str, str]):
    """TC-DASH-03: Analyst JWT must access dashboard summary."""
    response = await client.get("/api/v1/dashboard/summary", headers=analyst_headers)
    assert_failure_status(response.status_code, 200)
    assert_success(response.json())
