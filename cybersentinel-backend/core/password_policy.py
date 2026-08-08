"""Production password policy enforcement."""

from __future__ import annotations

import re

_MIN_LENGTH = 12
_UPPER = re.compile(r"[A-Z]")
_LOWER = re.compile(r"[a-z]")
_DIGIT = re.compile(r"\d")
_SPECIAL = re.compile(r"[^A-Za-z0-9]")


def validate_password_strength(password: str) -> None:
    """
    Enforce production password requirements.
    Raises ValueError with a human-readable message on failure.
    """
    if len(password) < _MIN_LENGTH:
        raise ValueError(f"Password must be at least {_MIN_LENGTH} characters.")
    if not _UPPER.search(password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not _LOWER.search(password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not _DIGIT.search(password):
        raise ValueError("Password must contain at least one digit.")
    if not _SPECIAL.search(password):
        raise ValueError("Password must contain at least one special character.")
