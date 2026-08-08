"""
MITRE ATT&CK technique mapping for CyberSentinel attack types.

Maps granular attack labels and SOC rule names to ATT&CK technique IDs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class MitreMapping:
    attack_type: str
    mitre_id: str
    technique: str
    tactic: str


# Canonical attack type → ATT&CK mapping
_ATTACK_MAP: dict[str, MitreMapping] = {
    "Benign": MitreMapping("Benign", "—", "No malicious technique", "—"),
    "DDoS": MitreMapping("DDoS", "T1498", "Network Denial of Service", "Impact"),
    "DoS": MitreMapping("DoS", "T1499", "Endpoint Denial of Service", "Impact"),
    "PortScan": MitreMapping("PortScan", "T1046", "Network Service Discovery", "Discovery"),
    "Port Scan": MitreMapping("Port Scan", "T1046", "Network Service Discovery", "Discovery"),
    "Bot": MitreMapping("Bot", "T1071", "Application Layer Protocol", "Command and Control"),
    "Botnet": MitreMapping("Botnet", "T1071", "Application Layer Protocol", "Command and Control"),
    "Brute Force": MitreMapping("Brute Force", "T1110", "Brute Force", "Credential Access"),
    "Web Attack": MitreMapping("Web Attack", "T1190", "Exploit Public-Facing Application", "Initial Access"),
    "SYN Flood": MitreMapping("SYN Flood", "T1498", "Network Denial of Service", "Impact"),
    "SYN flood suspected": MitreMapping("SYN flood suspected", "T1498", "Network Denial of Service", "Impact"),
    "DDoS Spike": MitreMapping("DDoS Spike", "T1498", "Network Denial of Service", "Impact"),
    "DDoS behavior detected": MitreMapping("DDoS behavior detected", "T1498", "Network Denial of Service", "Impact"),
    "PortScan suspected": MitreMapping("PortScan suspected", "T1046", "Network Service Discovery", "Discovery"),
    "Malicious": MitreMapping("Malicious", "T1190", "Exploit Public-Facing Application", "Initial Access"),
    "Suspicious": MitreMapping("Suspicious", "T1046", "Network Service Discovery", "Discovery"),
    "Insufficient Evidence": MitreMapping("Insufficient Evidence", "—", "Insufficient telemetry", "—"),
    "Unknown": MitreMapping("Unknown", "—", "Unclassified activity", "—"),
}

# Rule trigger names → mapping keys
_RULE_ALIASES: dict[str, str] = {
    "PortScan suspected": "PortScan",
    "SYN flood suspected": "SYN Flood",
    "DDoS behavior detected": "DDoS",
    "Brute Force": "Brute Force",
    "Web Attack": "Web Attack",
}


def normalize_attack_type(label: str | None) -> str:
    """Normalize internal model labels to public attack type names."""
    if not label:
        return "Unknown"
    normalized = label.strip()
    if normalized == "Bot":
        return "Botnet"
    if normalized == "Benign":
        return "Benign"
    return normalized


def map_attack_to_mitre(attack_type: str | None) -> MitreMapping:
    """Return MITRE ATT&CK mapping for an attack type or rule name."""
    if not attack_type:
        return _ATTACK_MAP["Unknown"]
    key = _RULE_ALIASES.get(attack_type, attack_type)
    key = normalize_attack_type(key)
    return _ATTACK_MAP.get(key, _ATTACK_MAP["Unknown"])


def mitre_from_rules(triggered_rules: list[str]) -> Optional[MitreMapping]:
    """Pick the highest-priority MITRE mapping from triggered SOC rules."""
    priority = ("DDoS", "SYN Flood", "Brute Force", "DoS", "Web Attack", "Port Scan", "PortScan")
    for name in priority:
        for rule in triggered_rules:
            if name.lower() in rule.lower():
                return map_attack_to_mitre(rule)
    if triggered_rules:
        return map_attack_to_mitre(triggered_rules[0])
    return None


def mitre_to_dict(mapping: MitreMapping) -> dict[str, str]:
    return {
        "attack_type": mapping.attack_type,
        "mitre_id": mapping.mitre_id,
        "technique": mapping.technique,
        "tactic": mapping.tactic,
    }
