from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

import pandas as pd


LINUX_FIREWALL_LOG_PATHS = (
    "/var/log/ufw.log",
    "/var/log/kern.log",
    "/var/log/syslog",
    "/var/log/messages",
)

WINDOWS_FIREWALL_LOG_PATH = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

_SYSLOG_PREFIX_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
)


def read_firewall_log(path: str | Path, source: str = "auto") -> pd.DataFrame:
    """
    Read real firewall logs into the canonical schema used by the pipeline.

    Supported sources:
    - Windows Firewall pfirewall.log
    - Linux iptables/UFW kernel logs with SRC= DST= PROTO= DPT= fields
    """
    source = source.lower().strip()
    if source not in {"auto", "windows", "iptables", "linux"}:
        raise ValueError("source must be one of: auto, windows, iptables, linux")

    if source == "windows" or (source == "auto" and _looks_like_windows_firewall_log(path)):
        return read_windows_firewall_log(path)
    return read_iptables_firewall_log(path)


def find_default_firewall_log_paths() -> list[Path]:
    """Return existing OS firewall log paths without inventing synthetic training data."""
    candidates = [Path(WINDOWS_FIREWALL_LOG_PATH), *(Path(path) for path in LINUX_FIREWALL_LOG_PATHS)]
    return [path for path in candidates if path.exists()]

def read_windows_firewall_log(path: str) -> pd.DataFrame:
    """
    Reads pfirewall.log and maps Windows column names
    to CyberSentinel canonical column names.
    """
    log_path = Path(path)
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    # Skip comment lines starting with #
    rows = []
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            rows.append(line.split())

    if not rows:
        raise ValueError("Log file is empty or has no data rows.")

    # Windows firewall fixed column order
    windows_cols = [
        "date", "time", "action", "protocol",
        "src-ip", "dst-ip", "src-port", "dst-port",
        "size", "tcpflags", "tcpsyn", "tcpack",
        "tcpwin", "icmptype", "icmpcode", "info", "path"
    ]

    df = pd.DataFrame(rows)

    # Only take columns we have
    col_count = min(len(windows_cols), df.shape[1])
    df.columns = windows_cols[:col_count]

    # Build canonical columns your pipeline expects
    df["timestamp"] = pd.to_datetime(
        df["date"] + " " + df["time"],
        errors="coerce"
    )
    df["src_ip"]   = df["src-ip"]
    df["dst_ip"]   = df["dst-ip"]
    df["dst_port"] = pd.to_numeric(df["dst-port"], errors="coerce")
    df["protocol"] = df["protocol"].str.upper()
    df["pkt_size"] = pd.to_numeric(df["size"], errors="coerce").fillna(400)
    df["action"]   = df["action"].str.upper()
    df["is_block"] = df["action"].isin(["DROP", "DENY", "BLOCK"]).astype(int)

    # Drop rows with missing critical fields
    df = df.dropna(subset=["timestamp", "src_ip", "dst_ip", "dst_port"])

    return df[[
        "timestamp", "src_ip", "dst_ip",
        "dst_port", "protocol", "pkt_size",
        "is_block", "action"
    ]]


def read_iptables_firewall_log(path: str | Path) -> pd.DataFrame:
    """Read Linux iptables/UFW-style firewall records from syslog text files."""
    log_path = Path(path)
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    rows = []
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            fields = _parse_iptables_line(line)
            if fields:
                rows.append(fields)

    if not rows:
        raise ValueError(
            "Log file has no iptables/UFW firewall rows with SRC, DST, PROTO, and DPT fields."
        )

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["src_ip"] = df["SRC"]
    df["dst_ip"] = df["DST"]
    df["dst_port"] = pd.to_numeric(df["DPT"], errors="coerce")
    df["protocol"] = df["PROTO"].astype(str).str.upper()
    df["pkt_size"] = pd.to_numeric(df.get("LEN"), errors="coerce").fillna(400)
    df["action"] = df["action"].astype(str).str.upper()
    df["is_block"] = df["action"].isin(["BLOCK", "DROP", "DENY", "REJECT"]).astype(int)
    df = df.dropna(subset=["timestamp", "src_ip", "dst_ip", "dst_port"])

    return df[
        [
            "timestamp",
            "src_ip",
            "dst_ip",
            "dst_port",
            "protocol",
            "pkt_size",
            "is_block",
            "action",
        ]
    ]


def _parse_iptables_line(line: str) -> dict[str, object] | None:
    if "SRC=" not in line or "DST=" not in line or "PROTO=" not in line:
        return None

    fields = {}
    for token in line.strip().split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value

    if not {"SRC", "DST", "PROTO"}.issubset(fields):
        return None
    if "DPT" not in fields and fields.get("PROTO", "").upper() not in {"ICMP", "ICMPV6"}:
        return None

    timestamp = _parse_syslog_timestamp(line) or datetime.now().replace(microsecond=0)
    action = _infer_linux_action(line)
    fields["timestamp"] = timestamp
    fields["DPT"] = fields.get("DPT", "0")
    fields["action"] = action
    return fields


def _parse_syslog_timestamp(line: str) -> datetime | None:
    match = _SYSLOG_PREFIX_RE.match(line)
    if not match:
        return None
    current_year = datetime.now().year
    raw = f"{current_year} {match.group('month')} {match.group('day')} {match.group('time')}"
    return datetime.strptime(raw, "%Y %b %d %H:%M:%S")


def _infer_linux_action(line: str) -> str:
    upper = line.upper()
    if any(marker in upper for marker in ("UFW BLOCK", "IPTABLES-DROP", "DROP", "DENY", "REJECT")):
        return "DROP"
    if any(marker in upper for marker in ("UFW ALLOW", "ACCEPT", "ALLOW")):
        return "ALLOW"
    return "LOG"


def _looks_like_windows_firewall_log(path: str | Path) -> bool:
    text = str(path).lower()
    return "pfirewall" in text or text.endswith(".log") and "windows" in text
