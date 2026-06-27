"""Firewall analysis API tests — strict pass/fail assertions."""

from __future__ import annotations

import io

import pytest
from httpx import AsyncClient

from tests.helpers import FIREWALL_INGEST_EVENT, IPTABLES_LOG_CONTENT, assert_failure_status, assert_success


@pytest.mark.asyncio
async def test_tc_fw_01_analyze_requires_authentication(client: AsyncClient):
    """TC-FW-01: POST /firewall/analyze without JWT must return 401."""
    response = await client.post(
        "/api/v1/firewall/analyze",
        files={"file": ("fw.log", io.BytesIO(IPTABLES_LOG_CONTENT.encode()), "text/plain")},
    )
    assert_failure_status(response.status_code, 401)


@pytest.mark.asyncio
async def test_tc_fw_02_analyze_log_file(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-FW-02: Valid iptables log upload must return HTTP 200."""
    response = await client.post(
        "/api/v1/firewall/analyze",
        headers=admin_headers,
        files={"file": ("fw.log", io.BytesIO(IPTABLES_LOG_CONTENT.encode()), "text/plain")},
    )
    assert_failure_status(response.status_code, 200, response.text)
    body = response.json()
    assert_success(body)
    assert body["validation_report"]["valid_rows"] >= 1


@pytest.mark.asyncio
async def test_tc_fw_03_upload_alias_route(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-FW-03: POST /firewall/upload must behave like /analyze."""
    response = await client.post(
        "/api/v1/firewall/upload",
        headers=admin_headers,
        files={"file": ("fw.log", io.BytesIO(IPTABLES_LOG_CONTENT.encode()), "text/plain")},
    )
    assert_failure_status(response.status_code, 200, response.text)
    assert_success(response.json())


@pytest.mark.asyncio
async def test_tc_fw_04_ingest_realtime_event(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-FW-04: POST /firewall/ingest must accept a single event."""
    response = await client.post(
        "/api/v1/firewall/ingest",
        headers=admin_headers,
        json={"event": FIREWALL_INGEST_EVENT},
    )
    assert_failure_status(response.status_code, 200, response.text)
    body = response.json()
    assert_success(body)
    assert body["buffered_events"] >= 1


@pytest.mark.asyncio
async def test_tc_fw_05_alerts_list(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-FW-05: GET /firewall/alerts must return paginated alerts."""
    response = await client.get("/api/v1/firewall/alerts", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert "alerts" in body
    assert "total" in body


@pytest.mark.asyncio
async def test_tc_fw_06_alerts_csv_export(client: AsyncClient, analyst_headers: dict[str, str]):
    """TC-FW-06: Analyst must export alerts CSV with HTTP 200."""
    response = await client.get("/api/v1/firewall/alerts.csv", headers=analyst_headers)
    assert_failure_status(response.status_code, 200)
    assert response.headers["content-type"].startswith("text/csv")


@pytest.mark.asyncio
async def test_tc_fw_07_monitor_status(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-FW-07: GET /firewall/monitor/status must return idle status."""
    response = await client.get("/api/v1/firewall/monitor/status", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    assert_success(response.json())


@pytest.mark.asyncio
async def test_tc_fw_08_intel_ip_lookup(client: AsyncClient, analyst_headers: dict[str, str]):
    """TC-FW-08: GET /firewall/intel/ip/{ip} must return enrichment payload."""
    response = await client.get("/api/v1/firewall/intel/ip/8.8.8.8", headers=analyst_headers)
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert body["ip"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_tc_fw_09_acknowledge_unknown_alert_returns_404(
    client: AsyncClient,
    admin_headers: dict[str, str],
):
    """TC-FW-09: PATCH unknown alert id must return 404."""
    response = await client.patch(
        "/api/v1/firewall/alerts/does-not-exist/acknowledge",
        headers=admin_headers,
    )
    assert_failure_status(response.status_code, 404)
