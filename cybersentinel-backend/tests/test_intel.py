"""Threat intel API tests — strict pass/fail assertions."""

from __future__ import annotations

import io

import pytest
from httpx import AsyncClient

from tests.helpers import assert_failure_status, assert_success


@pytest.mark.asyncio
async def test_tc_intel_01_file_requires_authentication(client: AsyncClient):
    """TC-INTEL-01: File scan without JWT must return 401."""
    response = await client.post(
        "/api/v1/intel/file",
        files={"file": ("sample.txt", io.BytesIO(b"hello"), "text/plain")},
    )
    assert_failure_status(response.status_code, 401)


@pytest.mark.asyncio
async def test_tc_intel_02_file_scan_returns_hash(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-INTEL-02: File upload must return HTTP 200 with lookup_key."""
    response = await client.post(
        "/api/v1/intel/file",
        headers=admin_headers,
        files={"file": ("sample.txt", io.BytesIO(b"cybersentinel-test"), "text/plain")},
    )
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert len(body["lookup_key"]) == 64


@pytest.mark.asyncio
async def test_tc_intel_03_url_scan(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-INTEL-03: URL scan must return HTTP 200."""
    response = await client.post(
        "/api/v1/intel/url",
        headers=admin_headers,
        json={"url": "https://example.com"},
    )
    assert_failure_status(response.status_code, 200)
    assert_success(response.json())


@pytest.mark.asyncio
async def test_tc_intel_04_empty_url_returns_422(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-INTEL-04: Empty URL must return HTTP 422."""
    response = await client.post(
        "/api/v1/intel/url",
        headers=admin_headers,
        json={"url": ""},
    )
    assert_failure_status(response.status_code, 422)
