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
    """Build engine options — SSL and pooling for Supabase PostgreSQL."""
    kwargs: dict = {
        "echo": settings.DEBUG,
        "pool_pre_ping": True,
    }

    if settings.DATABASE_URL.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        return kwargs

    kwargs["pool_timeout"] = 30
    kwargs["pool_recycle"] = 1800

    connect_args: dict = {"ssl": "require", "timeout": 30}
    is_transaction_pool = ":6543" in settings.DATABASE_URL
    if is_transaction_pool:
        connect_args["statement_cache_size"] = 0
        kwargs["connect_args"] = connect_args
        # Supabase transaction pooler (port 6543) — higher concurrency.
        kwargs["pool_size"] = 5
        kwargs["max_overflow"] = 5
    else:
        # Supabase session pooler (port 5432) — hard limit ~15 connections total.
        kwargs["connect_args"] = connect_args
        kwargs["pool_size"] = 2
        kwargs["max_overflow"] = 2
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


_TENANT_TABLES = (
    "packet_events",
    "firewall_alerts",
    "response_actions",
    "virus_scan_cache",
    "ip_reputation_cache",
)


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

    for table in _TENANT_TABLES:
        cols = await conn.execute(text(f"PRAGMA table_info({table})"))
        present = {row[1] for row in cols.fetchall()}
        if present and "user_id" not in present:
            await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN user_id VARCHAR(36)"))
            await conn.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{table}_user_id ON {table}(user_id)"))

    await _backfill_orphan_tenant_rows(conn, postgres=False)


async def _ensure_postgres_migrations(conn) -> None:
    """Lightweight column migrations for Supabase / PostgreSQL (public schema)."""
    await _ensure_postgres_table_columns(
        conn,
        "users",
        {
            "password_reset_token_hash": "VARCHAR(64)",
            "password_reset_expires": "VARCHAR(32)",
        },
        renames={"username": "email"},
    )
    await _ensure_postgres_table_columns(
        conn,
        "ip_reputation_cache",
        {
            "asn": "VARCHAR(16)",
            "as_org": "VARCHAR(256)",
        },
    )

    result = await conn.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = 'users'"
        )
    )
    user_present = {row[0] for row in result.fetchall()}
    if user_present and "email" in user_present:
        await conn.execute(
            text("UPDATE users SET email = email || '@cybersentinel.local' WHERE email NOT LIKE '%@%'")
        )

    for table in _TENANT_TABLES:
        await _ensure_postgres_table_columns(conn, table, {"user_id": "VARCHAR(36)"})

    await _ensure_postgres_tenant_unique_indexes(conn)
    await _backfill_orphan_tenant_rows(conn, postgres=True)


async def _ensure_postgres_table_columns(
    conn,
    table: str,
    columns: dict[str, str],
    *,
    renames: dict[str, str] | None = None,
) -> None:
    result = await conn.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = :table"
        ),
        {"table": table},
    )
    present = {row[0] for row in result.fetchall()}
    if not present:
        return

    for old_name, new_name in (renames or {}).items():
        if old_name in present and new_name not in present:
            await conn.execute(text(f"ALTER TABLE {table} RENAME COLUMN {old_name} TO {new_name}"))
            if new_name == "email":
                await conn.execute(text(f"ALTER TABLE {table} ALTER COLUMN {new_name} TYPE VARCHAR(255)"))
            present.remove(old_name)
            present.add(new_name)

    for name, ddl in columns.items():
        if name not in present:
            await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


async def _backfill_orphan_tenant_rows(conn, *, postgres: bool) -> None:
    """Assign legacy rows (user_id IS NULL) to the default admin account."""
    admin_email = settings.default_admin_email
    if postgres:
        admin_row = await conn.execute(
            text("SELECT id FROM users WHERE email = :email LIMIT 1"),
            {"email": admin_email},
        )
    else:
        admin_row = await conn.execute(
            text("SELECT id FROM users WHERE email = :email LIMIT 1"),
            {"email": admin_email},
        )
    row = admin_row.first()
    if not row:
        return
    admin_id = row[0]
    for table in _TENANT_TABLES:
        await conn.execute(
            text(f"UPDATE {table} SET user_id = :admin_id WHERE user_id IS NULL"),
            {"admin_id": admin_id},
        )


async def _ensure_postgres_tenant_unique_indexes(conn) -> None:
    """Replace global unique keys with per-user composite indexes on Supabase."""
    await conn.execute(
        text(
            "ALTER TABLE virus_scan_cache "
            "DROP CONSTRAINT IF EXISTS virus_scan_cache_lookup_key_key"
        )
    )
    # Legacy SQLAlchemy / Supabase unique index on lookup_key alone (blocks per-user rows).
    await conn.execute(text("DROP INDEX IF EXISTS ix_virus_scan_cache_lookup_key"))
    await conn.execute(
        text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_virus_scan_cache_user_lookup "
            "ON virus_scan_cache (user_id, lookup_key, scan_type)"
        )
    )
    await conn.execute(
        text(
            "ALTER TABLE ip_reputation_cache "
            "DROP CONSTRAINT IF EXISTS ip_reputation_cache_ip_address_key"
        )
    )
    await conn.execute(text("DROP INDEX IF EXISTS ix_ip_reputation_cache_ip_address"))
    await conn.execute(
        text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_ip_reputation_cache_user_ip "
            "ON ip_reputation_cache (user_id, ip_address)"
        )
    )


async def check_database() -> bool:
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return True
