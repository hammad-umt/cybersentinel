"""Packet classification API tests — strict pass/fail assertions."""

from __future__ import annotations

import io

import pytest
from httpx import AsyncClient

from tests.helpers import (
    BATCH_CSV,
    SAMPLE_FLOW,
    SPARSE_FLOW,
    assert_failure_status,
    assert_success,
)


@pytest.mark.asyncio
async def test_tc_pkt_01_classify_requires_authentication(client: AsyncClient):
    """TC-PKT-01: POST /packet/classify without JWT must return 401."""
    response = await client.post("/api/v1/packet/classify", json={"flow": SAMPLE_FLOW})
    assert_failure_status(response.status_code, 401)


@pytest.mark.asyncio
async def test_tc_pkt_02_classify_valid_flow_returns_prediction(
    client: AsyncClient,
    admin_headers: dict[str, str],
):
    """TC-PKT-02: Valid flow must return HTTP 200 with a Normal prediction."""
    response = await client.post(
        "/api/v1/packet/classify",
        headers=admin_headers,
        json={"flow": SAMPLE_FLOW},
    )
    assert_failure_status(response.status_code, 200, response.text)
    body = response.json()
    assert_success(body)
    assert body["result"]["prediction"] == "Normal"
    assert 0 <= body["result"]["risk_score"] <= 100


@pytest.mark.asyncio
async def test_tc_pkt_03_classify_sparse_flow_marks_insufficient_rf_evidence(
    client: AsyncClient,
    admin_headers: dict[str, str],
):
    """TC-PKT-03: Sparse flow must mark RF as Insufficient Evidence (SOC fusion may escalate)."""
    response = await client.post(
        "/api/v1/packet/classify",
        headers=admin_headers,
        json={"flow": SPARSE_FLOW},
    )
    assert_failure_status(response.status_code, 200, response.text)
    result = response.json()["result"]
    assert result["rf_prediction"] == "Insufficient Evidence"
    assert result["prediction"] == "Suspicious"
    assert result["risk_score"] == 40.0
    assert "RF weak confidence" in result["triggered_rules"]


@pytest.mark.asyncio
async def test_tc_pkt_04_events_list_paginated(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-PKT-04: GET /packet/events must return paginated list."""
    await client.post(
        "/api/v1/packet/classify",
        headers=admin_headers,
        json={"flow": SAMPLE_FLOW},
    )
    response = await client.get("/api/v1/packet/events", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert body["total"] >= 1
    assert isinstance(body["events"], list)


@pytest.mark.asyncio
async def test_tc_pkt_05_events_csv_export(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-PKT-05: GET /packet/events.csv must return CSV."""
    response = await client.get("/api/v1/packet/events.csv", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    assert response.headers["content-type"].startswith("text/csv")


@pytest.mark.asyncio
async def test_tc_pkt_06_batch_rejects_non_csv(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-PKT-06: Batch upload must reject non-CSV files with 400."""
    response = await client.post(
        "/api/v1/packet/classify/batch",
        headers=admin_headers,
        files={"file": ("bad.txt", io.BytesIO(b"not csv"), "text/plain")},
    )
    assert_failure_status(response.status_code, 400)


@pytest.mark.asyncio
async def test_tc_pkt_07_batch_csv_classifies_rows(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-PKT-07: Valid CSV batch must return HTTP 200 with results."""
    response = await client.post(
        "/api/v1/packet/classify/batch",
        headers=admin_headers,
        files={"file": ("flows.csv", io.BytesIO(BATCH_CSV.encode()), "text/csv")},
    )
    assert_failure_status(response.status_code, 200, response.text)
    body = response.json()
    assert_success(body)
    assert body["total_flows"] >= 1
