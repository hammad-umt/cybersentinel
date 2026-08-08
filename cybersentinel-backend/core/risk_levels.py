"""
Unified risk level vocabulary for threat scoring and incidents.

Risk levels (0–100):
  0–20   Safe
  21–40  Low
  41–60  Medium
  61–80  High
  81–100 Critical
"""

from __future__ import annotations

SAFE = "Safe"
LOW = "Low"
MEDIUM = "Medium"
HIGH = "High"
CRITICAL = "Critical"

PUBLIC_RISK_LEVELS = frozenset({SAFE, LOW, MEDIUM, HIGH, CRITICAL})

# Incident auto-creation threshold
INCIDENT_AUTO_CREATE_SCORE = 61.0


def score_to_risk_level(score: float) -> str:
    """Map a 0–100 threat score to the public risk level."""
    value = max(0.0, min(float(score), 100.0))
    if value <= 20.0:
        return SAFE
    if value <= 40.0:
        return LOW
    if value <= 60.0:
        return MEDIUM
    if value <= 80.0:
        return HIGH
    return CRITICAL


def is_critical_attack(attack_type: str | None, risk_level: str) -> bool:
    """True when attack type or risk warrants automatic incident creation."""
    if risk_level in {HIGH, CRITICAL}:
        return True
    if not attack_type:
        return False
    critical_types = {"DDoS", "DoS", "Brute Force", "Botnet", "Web Attack", "SYN Flood", "DDoS Spike"}
    return normalize_attack_label(attack_type) in critical_types


def normalize_attack_label(label: str) -> str:
    if label == "Bot":
        return "Botnet"
    return label
