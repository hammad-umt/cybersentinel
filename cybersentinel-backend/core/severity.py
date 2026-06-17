"""
core/severity.py

Public severity vocabulary for API responses.

Clients always see Low / Medium / High / Critical. Internal firewall-pipeline
labels (Normal, Suspicious, Malicious-like, Critical) stay in the database and
unsupervised_learning code; translate at the API boundary.
"""

from __future__ import annotations

LOW = "Low"
MEDIUM = "Medium"
HIGH = "High"
CRITICAL = "Critical"

PUBLIC_SEVERITIES = frozenset({LOW, MEDIUM, HIGH, CRITICAL})

# Internal firewall-pipeline labels (stored in DB, not returned to clients).
_FIREWALL_INTERNAL = frozenset({"Normal", "Suspicious", "Malicious-like", "Critical"})

_FIREWALL_TO_PUBLIC: dict[str, str] = {
    "Normal": LOW,
    "Suspicious": MEDIUM,
    "Malicious-like": HIGH,
    "Malicious": HIGH,
    "Critical": CRITICAL,
}

_PUBLIC_TO_FIREWALL: dict[str, str] = {
    LOW: "Normal",
    MEDIUM: "Suspicious",
    HIGH: "Malicious-like",
    CRITICAL: "Critical",
}


def score_to_public_severity(score: float) -> str:
    """Map a 0-100 threat score to the public severity label."""
    if score >= 80:
        return CRITICAL
    if score >= 60:
        return HIGH
    if score >= 35:
        return MEDIUM
    return LOW


def translate_firewall_severity(internal: str) -> str:
    """Translate an internal firewall severity to the public vocabulary."""
    return _FIREWALL_TO_PUBLIC.get(internal, internal)


def public_to_firewall_severity(public: str) -> str | None:
    """
    Translate a public severity filter to the internal DB label.
    Returns None when the value is not a recognized public or legacy label.
    """
    if public in _PUBLIC_TO_FIREWALL:
        return _PUBLIC_TO_FIREWALL[public]
    if public in _FIREWALL_INTERNAL:
        return public
    return None


def is_elevated_firewall_severity(internal: str) -> bool:
    """True when an internal firewall severity is Medium-equivalent or above."""
    return internal in {"Suspicious", "Malicious-like", "Critical"}
