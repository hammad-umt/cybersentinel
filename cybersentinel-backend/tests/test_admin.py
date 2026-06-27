"""Admin API tests — strict pass/fail assertions."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.helpers import assert_failure_status, assert_success


@pytest.mark.asyncio
async def test_tc_adm_01_reload_requires_authentication(client: AsyncClient):
    """TC-ADM-01: Reload models without JWT must return 401."""
    response = await client.post("/api/v1/admin/reload-models")
    assert_failure_status(response.status_code, 401)


@pytest.mark.asyncio
async def test_tc_adm_02_reload_as_admin(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-ADM-02: Admin reload must return HTTP 200 with model flags."""
    response = await client.post("/api/v1/admin/reload-models", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert body["packet_classifier_available"] is True
    assert body["firewall_pipeline_available"] is True


@pytest.mark.asyncio
async def test_tc_adm_03_reload_as_analyst_forbidden(client: AsyncClient, analyst_headers: dict[str, str]):
    """TC-ADM-03: Analyst reload must return HTTP 403."""
    response = await client.post("/api/v1/admin/reload-models", headers=analyst_headers)
    assert_failure_status(response.status_code, 403)
