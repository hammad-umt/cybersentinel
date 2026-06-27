"""Security Copilot API tests — strict pass/fail assertions."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.helpers import assert_failure_status, assert_success


@pytest.mark.asyncio
async def test_tc_cop_01_ask_requires_authentication(client: AsyncClient):
    """TC-COP-01: Copilot without JWT must return 401."""
    response = await client.post(
        "/api/v1/copilot/ask",
        json={"question": "What are the top threats?"},
    )
    assert_failure_status(response.status_code, 401)


@pytest.mark.asyncio
async def test_tc_cop_02_ask_returns_answer(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-COP-02: Copilot ask must return HTTP 200 with non-empty answer."""
    response = await client.post(
        "/api/v1/copilot/ask",
        headers=admin_headers,
        json={"question": "Summarize current SOC activity"},
    )
    assert_failure_status(response.status_code, 200)
    body = response.json()
    assert_success(body)
    assert len(body["answer"]) > 0


@pytest.mark.asyncio
async def test_tc_cop_03_query_alias(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-COP-03: /copilot/query alias must return HTTP 200."""
    response = await client.post(
        "/api/v1/copilot/query",
        headers=admin_headers,
        json={"question": "Any critical alerts today?"},
    )
    assert_failure_status(response.status_code, 200)
    assert_success(response.json())


@pytest.mark.asyncio
async def test_tc_cop_04_short_question_returns_422(client: AsyncClient, admin_headers: dict[str, str]):
    """TC-COP-04: Question shorter than 3 chars must return HTTP 422."""
    response = await client.post(
        "/api/v1/copilot/ask",
        headers=admin_headers,
        json={"question": "hi"},
    )
    assert_failure_status(response.status_code, 422)
