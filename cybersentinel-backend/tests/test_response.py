"""Response actions API tests — strict pass/fail assertions."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.helpers import assert_failure_status, assert_success


@pytest.mark.asyncio
async def test_tc_resp_01_requires_authentication(client: AsyncClient):
    """TC-RESP-01: POST /response/actions without JWT must return 401."""
    response = await client.post(
        "/api/v1/response/actions",
        json={"target_ip": "10.0.0.5", "action": "block_ip"},
    )
    assert_failure_status(response.status_code, 401)


@pytest.mark.asyncio
async def test_tc_resp_02_create_dry_run_action(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-RESP-02: Dry-run block_ip must return HTTP 200."""
    response = await client.post(
        "/api/v1/response/actions",
        headers=admin_headers,
        json={
            "target_ip": "10.0.0.5",
            "action": "block_ip",
            "reason": "pytest",
            "execute": False,
        },
    )
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert body["action"]["target_ip"] == "10.0.0.5"


@pytest.mark.asyncio
async def test_tc_resp_03_list_actions(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-RESP-03: GET /response/actions must return audit log."""
    response = await client.get("/api/v1/response/actions", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert isinstance(body["actions"], list)


@pytest.mark.asyncio
async def test_tc_resp_04_whitelist_action(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-RESP-04: Whitelist action type must be accepted."""
    response = await client.post(
        "/api/v1/response/actions",
        headers=admin_headers,
        json={"target_ip": "192.168.1.1", "action": "whitelist"},
    )
    assert_failure_status(response.status_code, 200)
    assert_success(response.json())
