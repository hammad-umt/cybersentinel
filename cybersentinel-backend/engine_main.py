"""
Desktop engine entry point for PyInstaller.

The Flutter app spawns cybersentinel_engine on startup; this module binds
only to 127.0.0.1 and loads engine.env from the install folder.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _application_root() -> Path:
    if _is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _configure_desktop_runtime() -> None:
    if not _is_frozen():
        return

    root = _application_root()
    os.environ.setdefault("HOST", "127.0.0.1")
    os.environ.setdefault(
        "SUPERVISED_MODEL_DIR",
        str(root / "supervised_learning" / "models"),
    )
    os.environ.setdefault(
        "UNSUPERVISED_MODEL_DIR",
        str(root / "unsupervised_learning" / "models"),
    )

    engine_env = root / "engine.env"
    if not engine_env.is_file():
        return

    try:
        from dotenv import load_dotenv

        load_dotenv(engine_env, override=False)
    except ImportError:
        for line in engine_env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key and key not in os.environ:
                os.environ[key] = value.strip().strip('"').strip("'")


_configure_desktop_runtime()


def main() -> None:
    import uvicorn

    from core.config import settings

    host = settings.HOST
    if host in {"0.0.0.0", "::"}:
        host = "127.0.0.1"

    uvicorn.run(
        "main:app",
        host=host,
        port=settings.PORT,
        log_level="info" if not settings.DEBUG else "debug",
        access_log=settings.DEBUG,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
