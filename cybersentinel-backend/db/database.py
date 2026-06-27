"""
db/database.py

Async SQLAlchemy engine and session factory for CyberSentinel.

Primary deployment database: Supabase (managed PostgreSQL on cloud).
Set DATABASE_URL in .env to your Supabase connection string.
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


def _engine_kwargs() -> dict:
    """Build engine options — SSL and pooling for cloud Supabase."""
    kwargs: dict = {
        "echo": settings.DEBUG,
        "pool_pre_ping": True,
    }

    if settings.DATABASE_URL.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        return kwargs

    if settings.uses_cloud_postgres:
        # Supabase cloud requires SSL on direct and pooler connections.
        connect_args: dict = {"ssl": "require"}
        # Transaction pooler (port 6543) — disable prepared statement cache for PgBouncer.
        if ":6543" in settings.DATABASE_URL:
            connect_args["statement_cache_size"] = 0
        kwargs["connect_args"] = connect_args
        kwargs["pool_size"] = 5
        kwargs["max_overflow"] = 10

    return kwargs


engine = create_async_engine(settings.DATABASE_URL, **_engine_kwargs())

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_tables() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _ensure_column_migrations(conn)


async def _ensure_column_migrations(conn) -> None:
    if settings.DATABASE_URL.startswith("sqlite"):
        await _ensure_sqlite_migrations(conn)
    elif settings.uses_cloud_postgres or settings.DATABASE_URL.startswith("postgresql"):
        await _ensure_postgres_migrations(conn)


async def _ensure_sqlite_migrations(conn) -> None:
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

    user_cols = await conn.execute(text("PRAGMA table_info(users)"))
    user_present = {row[1] for row in user_cols.fetchall()}
    if not user_present:
        return
    if "username" in user_present and "email" not in user_present:
        await conn.execute(text("ALTER TABLE users RENAME COLUMN username TO email"))
        user_present.remove("username")
        user_present.add("email")
    if "password_reset_token_hash" not in user_present:
        await conn.execute(text("ALTER TABLE users ADD COLUMN password_reset_token_hash VARCHAR(64)"))
    if "password_reset_expires" not in user_present:
        await conn.execute(text("ALTER TABLE users ADD COLUMN password_reset_expires VARCHAR(32)"))

    await conn.execute(
        text("UPDATE users SET email = email || '@cybersentinel.local' WHERE email NOT LIKE '%@%'")
    )


async def _ensure_postgres_migrations(conn) -> None:
    result = await conn.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = 'users'"
        )
    )
    user_present = {row[0] for row in result.fetchall()}
    if not user_present:
        return

    if "username" in user_present and "email" not in user_present:
        await conn.execute(text("ALTER TABLE users RENAME COLUMN username TO email"))
        await conn.execute(text("ALTER TABLE users ALTER COLUMN email TYPE VARCHAR(255)"))
        user_present.remove("username")
        user_present.add("email")

    if "password_reset_token_hash" not in user_present:
        await conn.execute(text("ALTER TABLE users ADD COLUMN password_reset_token_hash VARCHAR(64)"))
    if "password_reset_expires" not in user_present:
        await conn.execute(text("ALTER TABLE users ADD COLUMN password_reset_expires VARCHAR(32)"))

    await conn.execute(
        text("UPDATE users SET email = email || '@cybersentinel.local' WHERE email NOT LIKE '%@%'")
    )


async def check_database() -> bool:
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return True
