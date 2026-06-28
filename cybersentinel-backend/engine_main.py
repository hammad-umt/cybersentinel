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


def _write_engine_log(message: str) -> None:
    try:
        log_path = _application_root() / "engine.log"
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message.rstrip() + "\n")
    except OSError:
        pass


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
        if _is_frozen():
            msg = (
                f"Missing engine.env next to {sys.executable}. "
                "Reinstall CyberSentinel or restore engine.env from the installer."
            )
            print(f"ERROR: {msg}", file=sys.stderr)
            _write_engine_log(msg)
            sys.exit(1)
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
    try:
        import uvicorn

        from core.config import settings
    except Exception as exc:
        msg = f"Engine configuration failed: {exc}"
        print(f"ERROR: {msg}", file=sys.stderr)
        _write_engine_log(msg)
        sys.exit(1)

    if _is_frozen() and settings.DATABASE_URL.startswith("sqlite"):
        msg = (
            "Desktop engine requires Supabase PostgreSQL in engine.env "
            "(DATABASE_URL=postgresql+asyncpg://...)."
        )
        print(f"ERROR: {msg}", file=sys.stderr)
        _write_engine_log(msg)
        sys.exit(1)

    host = settings.HOST
    if host in {"0.0.0.0", "::"}:
        host = "127.0.0.1"

    # Pass the app object — not "main:app". String imports fail in PyInstaller
    # because main.py is not loaded unless referenced as a Python import.
    from main import app

    uvicorn.run(
        app,
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
    except Exception as exc:
        msg = f"Engine crashed: {exc}"
        print(f"ERROR: {msg}", file=sys.stderr)
        _write_engine_log(msg)
        sys.exit(1)
