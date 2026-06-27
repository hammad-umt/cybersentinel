"""Reports API tests — strict pass/fail assertions."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.helpers import assert_failure_status


@pytest.mark.asyncio
async def test_tc_rpt_01_pdf_requires_authentication(client: AsyncClient):
    """TC-RPT-01: PDF report without JWT must return 401."""
    response = await client.get("/api/v1/reports/summary.pdf")
    assert_failure_status(response.status_code, 401)


@pytest.mark.asyncio
async def test_tc_rpt_02_summary_pdf_download(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-RPT-02: PDF download must return HTTP 200 and valid PDF bytes."""
    response = await client.get("/api/v1/reports/summary.pdf", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content[:4] == b"%PDF"


@pytest.mark.asyncio
async def test_tc_rpt_03_pdf_alias_route(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-RPT-03: /reports/pdf alias must return HTTP 200 PDF."""
    response = await client.get("/api/v1/reports/pdf", headers=admin_headers)
    assert_failure_status(response.status_code, 200)
    assert response.content[:4] == b"%PDF"
