"""Packet capture API tests — strict pass/fail assertions."""

from __future__ import annotations

import io

import pytest
from httpx import AsyncClient

from tests.helpers import assert_failure_status, assert_success


@pytest.mark.asyncio
async def test_tc_cap_01_interfaces_requires_authentication(client: AsyncClient):
    """TC-CAP-01: GET /capture/interfaces without JWT must return 401."""
    response = await client.get("/api/v1/capture/interfaces")
    assert_failure_status(response.status_code, 401)


@pytest.mark.asyncio
async def test_tc_cap_02_interfaces_list(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-CAP-02: Interfaces endpoint must return HTTP 200."""
    response = await client.get("/api/v1/capture/interfaces", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert isinstance(body["interfaces"], list)


@pytest.mark.asyncio
async def test_tc_cap_03_capture_status(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-CAP-03: Capture status must return HTTP 200 when idle."""
    response = await client.get("/api/v1/capture/status", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    assert_success(response.json())


@pytest.mark.asyncio
async def test_tc_cap_04_capture_packets_buffer(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-CAP-04: GET /capture/packets must return HTTP 200."""
    response = await client.get("/api/v1/capture/packets", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    assert "packets" in response.json()


@pytest.mark.asyncio
async def test_tc_cap_05_stop_when_idle(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-CAP-05: POST /capture/stop when idle must return HTTP 200."""
    response = await client.post("/api/v1/capture/stop", headers=admin_headers)
    assert_failure_status(response.status_code, 200)


@pytest.mark.asyncio
async def test_tc_cap_06_import_requires_admin(client: AsyncClient, analyst_headers: dict[str, str]):
    """TC-CAP-06: PCAP import must return HTTP 403 for Analyst."""
    response = await client.post(
        "/api/v1/capture/import",
        headers=analyst_headers,
        files={"file": ("test.pcap", io.BytesIO(b"pcap"), "application/octet-stream")},
    )
    assert_failure_status(response.status_code, 403)


@pytest.mark.asyncio
async def test_tc_cap_07_import_rejects_invalid_file(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-CAP-07: PCAP import must return HTTP 400 for non-pcap file."""
    response = await client.post(
        "/api/v1/capture/import",
        headers=admin_headers,
        files={"file": ("bad.txt", io.BytesIO(b"not pcap"), "text/plain")},
    )
    assert_failure_status(response.status_code, 400)
