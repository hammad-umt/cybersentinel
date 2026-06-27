"""Threat scoring API tests — strict pass/fail assertions."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.helpers import assert_failure_status, assert_success


@pytest.mark.asyncio
async def test_tc_thr_01_score_requires_authentication(client: AsyncClient):
    """TC-THR-01: GET /threat/score/{ip} without JWT must return 401."""
    response = await client.get("/api/v1/threat/score/8.8.8.8")
    assert_failure_status(response.status_code, 401)


@pytest.mark.asyncio
async def test_tc_thr_02_score_returns_unified_fields(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-THR-02: Threat score must return final_score and severity."""
    response = await client.get("/api/v1/threat/score/8.8.8.8", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert body["ip"] == "8.8.8.8"
    assert 0 <= body["final_score"] <= 100
    assert body["severity"] in {"Low", "Medium", "High", "Critical"}


@pytest.mark.asyncio
async def test_tc_thr_03_top_threats_list(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-THR-03: GET /threat/top must return results list."""
    response = await client.get("/api/v1/threat/top", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert isinstance(body["results"], list)
    assert body["total"] >= 0


@pytest.mark.asyncio
async def test_tc_thr_04_top_threats_respects_limit(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-THR-04: limit query param must cap result count."""
    response = await client.get("/api/v1/threat/top?limit=3", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    assert len(response.json()["results"]) <= 3


@pytest.mark.asyncio
async def test_tc_thr_05_queue_ips(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-THR-05: POST /threat/queue must accept IP list and return queued count."""
    response = await client.post(
        "/api/v1/threat/queue",
        headers=admin_headers,
        json={"ips": ["8.8.8.8", "1.1.1.1"]},
    )
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert body["queued"] == 2


@pytest.mark.asyncio
async def test_tc_thr_06_queue_empty_list_returns_422(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-THR-06: Empty IP list must return 422 validation error."""
    response = await client.post(
        "/api/v1/threat/queue",
        headers=admin_headers,
        json={"ips": []},
    )
    assert_failure_status(response.status_code, 422)
