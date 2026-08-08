"""
Launcher for CyberSentinel backend.

When DEBUG=true, reload watches only application code and ignores `.venv` /
generated files. With DEBUG=false, reload is disabled for production-like runs.
"""

from __future__ import annotations

import sys
from pathlib import Path

import uvicorn

from core.config import BASE_DIR, settings


def _local_venv_python() -> Path | None:
    for name in ("venv", ".venv"):
        candidate = BASE_DIR / name / "Scripts" / "python.exe"
        if candidate.is_file():
            return candidate
    return None


def _xgboost_artifacts_present() -> bool:
    model_dir = settings.SUPERVISED_MODEL_DIR
    return (model_dir / "supervised_model.joblib").is_file() and (model_dir / "scaler.joblib").is_file()


def _ensure_xgboost_runtime() -> None:
    if not _xgboost_artifacts_present():
        return
    try:
        import xgboost  # noqa: F401
    except ModuleNotFoundError:
        venv_python = _local_venv_python()
        hint = (
            f"  {venv_python} run.py"
            if venv_python is not None
            else "  pip install xgboost"
        )
        print(
            "ERROR: XGBoost model artifacts are configured but the xgboost package "
            "is not installed for this Python interpreter.\n"
            f"  Current Python: {sys.executable}\n"
            "Fix one of:\n"
            "  pip install xgboost\n"
            f"{hint}\n",
            file=sys.stderr,
        )
        raise SystemExit(1)


if __name__ == "__main__":
    _ensure_xgboost_runtime()
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
