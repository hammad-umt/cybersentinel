from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


AnomalyLevel = Literal["Normal", "Suspicious", "Malicious"]


@dataclass
class FusionInput:
    ml_malicious_probability: float
    packet_anomaly_level: AnomalyLevel
    packet_anomaly_score: float
    firewall_anomaly_level: AnomalyLevel
    firewall_anomaly_score: float
    soc_rule_score: float
    ml_prediction: str = "Normal"
    ml_max_probability: float = 0.0
    triggered_rules: list[str] = field(default_factory=list)
    minimum_risk: float = 0.0


@dataclass
class FusionDecision:
    prediction: str
    risk_score: float


class SOCFusionEngine:
    """Final authority for packet risk decisions — cs-fyp-aligned 40/30/30 hybrid weights."""

    def decide(self, signal: FusionInput) -> FusionDecision:
        ml_score = _clamp(signal.ml_malicious_probability, 0.0, 1.0) * 100.0
        packet_score = _clamp(signal.packet_anomaly_score, 0.0, 100.0)
        firewall_score = _clamp(signal.firewall_anomaly_score, 0.0, 100.0)
        rule_score = _clamp(signal.soc_rule_score, 0.0, 100.0)

        # Supervised 40%, packet anomaly 30%, SIEM rules 30% (+ firewall context)
        supervised_component = ml_score * 0.40
        anomaly_component = packet_score * 0.30
        rules_component = rule_score * 0.30
        firewall_component = firewall_score * _anomaly_impact(signal.firewall_anomaly_level) * 0.20

        fused_risk = supervised_component + anomaly_component + rules_component + firewall_component
        minimum_risk = signal.minimum_risk
        trust_supervised = (
            signal.ml_prediction == "Normal"
            and signal.ml_max_probability >= 0.95
            and not signal.triggered_rules
        )
        if "Malicious" in {signal.packet_anomaly_level, signal.firewall_anomaly_level}:
            minimum_risk = max(minimum_risk, 70.0)
        elif not trust_supervised and "Suspicious" in {
            signal.packet_anomaly_level,
            signal.firewall_anomaly_level,
        }:
            minimum_risk = max(minimum_risk, 40.0)

        risk_score = round(_clamp(max(fused_risk, minimum_risk), 0.0, 100.0), 2)

        if "Malicious" in {signal.packet_anomaly_level, signal.firewall_anomaly_level}:
            prediction = "Malicious"
        elif risk_score >= 70.0:
            prediction = "Malicious"
        elif (
            risk_score >= 40.0
            or signal.triggered_rules
            or (
                not trust_supervised
                and "Suspicious" in {signal.packet_anomaly_level, signal.firewall_anomaly_level}
            )
        ):
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
