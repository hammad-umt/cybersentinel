"""
Launcher for CyberSentinel backend.

When DEBUG=true, reload watches only application code and ignores `.venv` /
generated files. With DEBUG=false, reload is disabled for production-like runs.
"""

from __future__ import annotations

from pathlib import Path

import uvicorn

from core.config import settings


BASE_DIR = Path(__file__).resolve().parent


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        reload_dirs=[
            str(BASE_DIR),
            str(BASE_DIR / "core"),
            str(BASE_DIR / "db"),
            str(BASE_DIR / "models"),
            str(BASE_DIR / "routers"),
            str(BASE_DIR / "schemas"),
            str(BASE_DIR / "services"),
        ],
        reload_excludes=[
            ".venv/*",
            "__pycache__/*",
            "*.pyc",
            "*.db",
            "*.sqlite",
        ],
    )
