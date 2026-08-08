"""Shared feature/class definitions — must match cybersentinel-backend/ml_engine/features.py."""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[2] / "cybersentinel-backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from ml_engine.features import ATTACK_CLASSES, FEATURE_NAMES  # noqa: E402

__all__ = ["ATTACK_CLASSES", "FEATURE_NAMES"]
