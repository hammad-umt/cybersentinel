"""
CICIDS-style signature SIEM rules — same logic as cs-fyp RuleEngine.

Evaluates the canonical 23-feature vector for deterministic attack signatures.
"""

from __future__ import annotations

from typing import Dict

from ml_engine.features import FEATURE_NAMES

# (score contribution, optional force_prediction, minimum_risk floor)
_SIGNATURE_POLICY: dict[str, tuple[float, str | None, float]] = {
    "SYN Flood": (40.0, "Malicious", 70.0),
    "Port Scan": (30.0, "Suspicious", 40.0),
    "DDoS Spike": (35.0, "Malicious", 70.0),
    "Brute Force": (40.0, "Malicious", 70.0),
    "DoS": (35.0, "Malicious", 70.0),
    "Web Attack": (30.0, "Suspicious", 40.0),
}


class SignatureRuleEngine:
    """Feature-signature rules complementing contextual SOC rules."""

    def evaluate(self, features: dict[str, float]) -> Dict[str, object]:
        f = {name: float(features.get(name, 0.0) or 0.0) for name in FEATURE_NAMES}
        triggered: list[str] = []

        if f["syn_flag_count"] > 30 and f["ack_flag_count"] < f["syn_flag_count"] * 0.25:
            triggered.append("SYN Flood")

        if f["unique_dest_ports"] > 10:
            triggered.append("Port Scan")

        if f["flow_packets_per_s"] > 500 or (
            f["flow_bytes_per_s"] > 1_000_000 and f["flow_packets_per_s"] > 250
        ):
            triggered.append("DDoS Spike")

        if f["failed_connections"] > 8:
            triggered.append("Brute Force")

        if f["rst_flag_count"] > 20 and f["flow_packets_per_s"] > 100:
            triggered.append("DoS")

        # PSH-heavy uploads alone match normal HTTPS; skip established sessions.
        if (
            f["psh_flag_count"] > 15
            and f["total_length_fwd"] > 5000
            and not (f["syn_flag_count"] <= 3 and f["ack_flag_count"] >= f["psh_flag_count"])
        ):
            triggered.append("Web Attack")

        if triggered:
            return {
                "rule_triggered": True,
                "attack_type": triggered[0],
                "all_rules": triggered,
            }
        return {"rule_triggered": False, "attack_type": "Benign", "all_rules": []}


def signature_rule_policy(rule_name: str) -> tuple[float, str | None, float]:
    return _SIGNATURE_POLICY.get(rule_name, (25.0, "Suspicious", 40.0))
