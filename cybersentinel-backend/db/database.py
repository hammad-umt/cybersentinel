"""
db/database.py

Async SQLAlchemy engine and session factory for CyberSentinel.

All database access in the app goes through:
  - get_db()  →  async context manager for FastAPI dependency injection
  - Base      →  declarative base that all ORM models inherit from

Usage in a router:
    from db.database import get_db
    from sqlalchemy.ext.asyncio import AsyncSession

    @router.get("/something")
    async def handler(db: AsyncSession = Depends(get_db)):
        ...
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import text
from sqlalchemy.orm import DeclarativeBase

from core.config import settings


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
# echo=True logs every SQL statement — useful for debugging, turn off in prod.
# connect_args only applies to SQLite to allow concurrent access.
# ---------------------------------------------------------------------------

_connect_args = (
    {"check_same_thread": False}
    if settings.DATABASE_URL.startswith("sqlite")
    else {}
)

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    connect_args=_connect_args,
    pool_pre_ping=True,        # verifies connection is alive before using it
)


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------
# expire_on_commit=False means ORM objects stay usable after commit,
# which is important in async code where you return objects from endpoints.
# ---------------------------------------------------------------------------

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ---------------------------------------------------------------------------
# Declarative base — all ORM models in db/models.py inherit from this
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Dependency — injected into FastAPI route handlers
# ---------------------------------------------------------------------------

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yields an async database session and guarantees it is closed
    after the request finishes, even if an exception is raised.

    FastAPI usage:
        db: AsyncSession = Depends(get_db)
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ---------------------------------------------------------------------------
# Table creation helper — called once at startup from main.py lifespan
# ---------------------------------------------------------------------------

async def create_tables() -> None:
    """
    Creates all tables defined in db/models.py if they don't exist.
    Safe to call on every startup — does nothing if tables already exist.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _ensure_column_migrations(conn)


async def _ensure_column_migrations(conn) -> None:
    """Add columns introduced after initial deploy without a full migration tool."""
    if not settings.DATABASE_URL.startswith("sqlite"):
        return

    columns = {
        "ip_reputation_cache": {
            "asn": "VARCHAR(16)",
            "as_org": "VARCHAR(256)",
        },
    }
    for table, defs in columns.items():
        existing = await conn.execute(text(f"PRAGMA table_info({table})"))
        present = {row[1] for row in existing.fetchall()}
        for name, ddl in defs.items():
            if name not in present:
                await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


async def check_database() -> bool:
    """Run a lightweight database connectivity check."""
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return True
