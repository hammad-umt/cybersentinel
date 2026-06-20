from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


AnomalyLevel = Literal["Normal", "Suspicious", "Malicious"]


@dataclass
class SOCRuleContext:
    src_ip: str | None = None
    distinct_dst_ports_short_window: int = 0
    flow_duration: float | None = None
    total_packets: float = 0.0
    flow_packets_per_second: float | None = None
    syn_count: float = 0.0
    ack_count: float = 0.0
    rf_prediction: str = "Normal"
    rf_max_probability: float = 0.0
    rf_malicious_probability: float = 0.0
    packet_anomaly_level: AnomalyLevel = "Normal"
    firewall_anomaly_level: AnomalyLevel = "Normal"


@dataclass
class SOCRuleResult:
    score: float = 0.0
    triggered_rules: list[str] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)
    force_prediction: str | None = None
    minimum_risk: float = 0.0


class SOCRuleEngine:
    """Deterministic attack rules that can only raise risk."""

    def evaluate(self, context: SOCRuleContext) -> SOCRuleResult:
        result = SOCRuleResult()

        if context.distinct_dst_ports_short_window >= 10:
            self._trigger(result, 30.0, "PortScan suspected", "Same source IP accessed many destination ports.")

        if self._is_ddos_burst(context):
            self._trigger(result, 35.0, "DDoS behavior detected", "High packet rate or short high-volume flow observed.")

        if context.syn_count >= 20 and context.ack_count <= max(3.0, context.syn_count * 0.2):
            self._trigger(result, 40.0, "SYN flood suspected", "SYN count is high while ACK count is low.")

        if context.firewall_anomaly_level == "Suspicious":
            self._trigger(result, 25.0, "Suspicious IP behavior", "Firewall behavior classified as Suspicious.")
        elif context.firewall_anomaly_level == "Malicious":
            result.force_prediction = "Malicious"
            result.minimum_risk = max(result.minimum_risk, 70.0)
            self._trigger(result, 45.0, "Malicious IP behavior", "Firewall behavior classified as Malicious.")

        if context.packet_anomaly_level == "Suspicious" and context.rf_prediction == "Normal":
            result.force_prediction = "Suspicious"
            result.minimum_risk = max(result.minimum_risk, 40.0)
            self._trigger(
                result,
                0.0,
                "Packet anomaly override",
                "RF classified as Normal but packet anomaly score is Suspicious.",
            )
        elif context.packet_anomaly_level == "Malicious":
            result.force_prediction = "Malicious"
            result.minimum_risk = max(result.minimum_risk, 70.0)
            self._trigger(
                result,
                45.0,
                "Malicious packet anomaly",
                "Packet anomaly score is Malicious.",
            )

        if context.rf_prediction == "Malicious" and context.rf_malicious_probability > 0.85:
            result.minimum_risk = max(result.minimum_risk, 70.0)
            self._trigger(
                result,
                0.0,
                "High confidence attack",
                "RF malicious probability exceeded 0.85, enforcing high-risk floor.",
            )

        if context.rf_max_probability < 0.60:
            result.force_prediction = "Suspicious"
            result.minimum_risk = max(result.minimum_risk, 40.0)
            self._trigger(
                result,
                0.0,
                "RF weak confidence",
                "RF confidence is low so uncertainty is handled as Suspicious.",
            )

        result.score = min(result.score, 100.0)
        return result

    @staticmethod
    def _trigger(result: SOCRuleResult, score: float, label: str, explanation: str) -> None:
        if label not in result.triggered_rules:
            result.triggered_rules.append(label)
        result.score += max(score, 0.0)
        result.explanation.append(explanation)

    @staticmethod
    def _is_ddos_burst(context: SOCRuleContext) -> bool:
        duration = context.flow_duration or 0.0
        duration_seconds = duration / 1_000_000.0 if duration > 10_000 else duration
        high_rate = (context.flow_packets_per_second or 0.0) >= 1000.0
        short_high_volume = duration_seconds > 0 and duration_seconds <= 1.0 and context.total_packets >= 100.0
        return high_rate or short_high_volume
