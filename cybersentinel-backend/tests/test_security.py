"""Core security module unit tests."""

from __future__ import annotations

from core.security import _JWT_ROLE_MAP, resolve_bearer_role, resolve_request_role


def test_tc_unit_sec_01_jwt_role_mapping():
    """TC-UNIT-SEC-01: Database roles map to internal auth roles."""
    assert _JWT_ROLE_MAP["Administrator"] == "admin"
    assert _JWT_ROLE_MAP["Analyst"] == "analyst"
    assert _JWT_ROLE_MAP["SeniorManagement"] == "manager"


def test_tc_unit_sec_02_resolve_bearer_invalid():
    """TC-UNIT-SEC-02: Invalid bearer token resolves to None."""
    assert resolve_bearer_role(None) is None
    assert resolve_bearer_role("Basic abc") is None
    assert resolve_bearer_role("Bearer not.valid.jwt") is None


def test_tc_unit_sec_03_resolve_request_jwt_only():
    """TC-UNIT-SEC-03: JWT takes precedence; API key ignored when disabled."""
    assert resolve_request_role(x_api_key="fake-key", authorization=None) is None
