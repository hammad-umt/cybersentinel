"""Shared pytest fixtures — in-memory SQLite, mocked ML models, JWT clients."""

from __future__ import annotations

import os

os.environ.setdefault("ALLOW_SQLITE_TESTS", "1")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("JWT_SECRET_KEY", "pytest-secret-key-at-least-32-characters-long")
os.environ.setdefault("DEFAULT_ADMIN_EMAIL", "admin@cybersentinel.local")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "admin123")
os.environ.setdefault("ALLOW_PUBLIC_SIGNUP", "true")
os.environ.setdefault("USE_API_KEY_AUTH", "false")
os.environ.setdefault("RESEND_API_KEY", "")
os.environ.setdefault("SMTP_HOST", "")
os.environ.setdefault("SMTP_FROM_EMAIL", "")
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")
os.environ.setdefault("FUSION_WEIGHT_PACKET", "0.30")
os.environ.setdefault("FUSION_WEIGHT_FIREWALL", "0.25")
os.environ.setdefault("FUSION_WEIGHT_IP_REPUTATION", "0.20")
os.environ.setdefault("FUSION_WEIGHT_VIRUSTOTAL", "0.15")
os.environ.setdefault("FUSION_WEIGHT_RULES", "0.10")

from core.config import get_settings

get_settings.cache_clear()

import pytest
from contextlib import asynccontextmanager
from httpx import ASGITransport, AsyncClient

from main import app
from models.loader import ModelRegistry
from tests.fakes import build_test_registry

ADMIN_EMAIL = "admin@cybersentinel.local"
ADMIN_PASSWORD = "admin123"
ANALYST_EMAIL = "analyst@example.com"
ANALYST_PASSWORD = "SecurePass123!Aa"
MANAGER_EMAIL = "manager@example.com"
MANAGER_PASSWORD = "SecurePass123!Aa"


@pytest.fixture(autouse=True)
def mock_ml_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test uses deterministic fake ML models (CI-safe, no .joblib files)."""

    async def _fake_load(cls: type[ModelRegistry]) -> ModelRegistry:
        return build_test_registry()

    monkeypatch.setattr(ModelRegistry, "load", classmethod(_fake_load))


@asynccontextmanager
async def _test_client():
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


@pytest.fixture
async def client() -> AsyncClient:
    async with _test_client() as ac:
        yield ac


@pytest.fixture
async def db_tables():
    """Create SQLite tables for service-layer unit tests that skip HTTP lifespan."""
    from db.database import create_tables

    await create_tables()


async def _login(client: AsyncClient, email: str, password: str) -> str:
    response = await client.post(
        "/api/v1/auth/token",
        data={"username": email, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture
async def admin_token(client: AsyncClient) -> str:
    return await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)


@pytest.fixture
def admin_headers(admin_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
async def analyst_headers(client: AsyncClient) -> dict[str, str]:
    register = await client.post(
        "/api/v1/auth/register",
        json={"email": ANALYST_EMAIL, "password": ANALYST_PASSWORD},
    )
    assert register.status_code == 201, register.text
    token = await _login(client, ANALYST_EMAIL, ANALYST_PASSWORD)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def manager_headers(client: AsyncClient, admin_headers: dict[str, str]) -> dict[str, str]:
    create = await client.post(
        "/api/v1/auth/users",
        headers=admin_headers,
        json={
            "email": MANAGER_EMAIL,
            "password": MANAGER_PASSWORD,
            "role": "SeniorManagement",
        },
    )
    assert create.status_code == 201, create.text
    token = await _login(client, MANAGER_EMAIL, MANAGER_PASSWORD)
    return {"Authorization": f"Bearer {token}"}
