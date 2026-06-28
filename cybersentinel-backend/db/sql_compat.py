"""
Database-specific SQL helpers.

Production uses Supabase (PostgreSQL). SQLite substr is kept only for pytest.
"""

from __future__ import annotations

import os

from sqlalchemy import String, cast, func
from sqlalchemy.sql.elements import Label

from core.config import settings


def iso_day_bucket(column) -> Label:
    """Bucket a UTC ISO-8601 timestamp column by calendar day (YYYY-MM-DD)."""
    as_text = cast(column, String)
    if settings.DATABASE_URL.startswith("sqlite") or os.getenv("ALLOW_SQLITE_TESTS") == "1" and settings.database_provider == "sqlite":
        return func.substr(as_text, 1, 10).label("day_bucket")
    return func.left(as_text, 10).label("day_bucket")
