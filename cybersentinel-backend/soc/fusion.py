from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


AnomalyLevel = Literal["Normal", "Suspicious", "Malicious"]


@dataclass
class FusionInput:
    rf_malicious_probability: float
    packet_anomaly_level: AnomalyLevel
    packet_anomaly_score: float
    firewall_anomaly_level: AnomalyLevel
    firewall_anomaly_score: float
    soc_rule_score: float
    triggered_rules: list[str] = field(default_factory=list)
    minimum_risk: float = 0.0


@dataclass
class FusionDecision:
    prediction: str
    risk_score: float


class SOCFusionEngine:
    """Final authority for packet risk decisions."""

    def decide(self, signal: FusionInput) -> FusionDecision:
        rf_score = _clamp(signal.rf_malicious_probability, 0.0, 1.0) * 100.0
        packet_score = _clamp(signal.packet_anomaly_score, 0.0, 100.0)
        firewall_score = _clamp(signal.firewall_anomaly_score, 0.0, 100.0)
        rule_score = _clamp(signal.soc_rule_score, 0.0, 100.0)

        packet_impact = _anomaly_impact(signal.packet_anomaly_level)
        firewall_impact = _anomaly_impact(signal.firewall_anomaly_level)
        base_risk = (rf_score * 0.45) + (packet_score * packet_impact) + (firewall_score * firewall_impact)
        fused_risk = base_risk + (rule_score * 0.10)
        minimum_risk = signal.minimum_risk
        if "Malicious" in {signal.packet_anomaly_level, signal.firewall_anomaly_level}:
            minimum_risk = max(minimum_risk, 70.0)
        elif "Suspicious" in {signal.packet_anomaly_level, signal.firewall_anomaly_level}:
            minimum_risk = max(minimum_risk, 40.0)

        risk_score = round(_clamp(max(fused_risk, minimum_risk), 0.0, 100.0), 2)

        if "Malicious" in {signal.packet_anomaly_level, signal.firewall_anomaly_level}:
            prediction = "Malicious"
        elif risk_score >= 70.0:
            prediction = "Malicious"
        elif risk_score >= 40.0 or signal.triggered_rules or "Suspicious" in {signal.packet_anomaly_level, signal.firewall_anomaly_level}:
            prediction = "Suspicious"
        else:
            prediction = "Normal"

        return FusionDecision(prediction=prediction, risk_score=risk_score)


def _clamp(value: float | None, low: float, high: float) -> float:
    try:
        number = float(value if value is not None else low)
    except (TypeError, ValueError):
        number = low
    return max(low, min(number, high))


def _anomaly_impact(level: str) -> float:
    if level == "Malicious":
        return 0.60
    if level == "Suspicious":
        return 0.30
    return 0.0
