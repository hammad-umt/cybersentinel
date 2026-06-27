"""
Database-specific SQL helpers.

CyberSentinel deploys on Supabase (PostgreSQL). SQLite is supported for local
tests only. Use these helpers instead of dialect-specific func.* calls inline.
"""

from __future__ import annotations

from sqlalchemy import String, cast, func
from sqlalchemy.sql.elements import Label

from core.config import settings


def iso_day_bucket(column) -> Label:
    """
    Bucket a UTC ISO-8601 timestamp column by calendar day (YYYY-MM-DD).

    Timestamps are stored as VARCHAR in the ORM. On Supabase/PostgreSQL we use
    ``left(cast(...), 10)``; SQLite uses ``substr``. Both paths use a single
    labeled expression so GROUP BY / ORDER BY satisfy PostgreSQL rules.
    """
    as_text = cast(column, String)
    if settings.uses_cloud_postgres:
        return func.left(as_text, 10).label("day_bucket")
    return func.substr(as_text, 1, 10).label("day_bucket")
