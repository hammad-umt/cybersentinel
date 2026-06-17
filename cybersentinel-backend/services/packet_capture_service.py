"""
services/packet_capture_service.py

Live packet capture and real-time Windows firewall log monitoring.

Two capture engines:
  1. Scapy  — pure Python, works on Windows with Npcap installed.
  2. TShark — subprocess-based, works if TShark/Wireshark is installed.

Real-time firewall monitor:
  - Tails Windows pfirewall.log for new lines
  - Each new line is sent to the unsupervised pipeline via ingest_realtime()

Windows requirements:
  - Scapy: install Npcap from https://npcap.com (NOT WinPcap)
  - TShark: install Wireshark from https://www.wireshark.org
  - Run backend as Administrator for raw socket access

Usage in router:
    service = PacketCaptureService(registry=request.app.state.models, db=db)
    await service.start_capture(request_body)
"""

from __future__ import annotations

import asyncio
import platform
import subprocess
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import AsyncSessionLocal
from db.models import PacketEvent
from models.loader import ModelRegistry
from schemas.capture import (
    CapturedPacketResult,
    CapturedPacketsResponse,
    CaptureStartRequest,
    CaptureStatusResponse,
    FirewallMonitorRequest,
    FirewallMonitorResponse,
    NetworkInterface,
)
from services.threat_scoring_service import ThreatScoringService

# ---------------------------------------------------------------------------
# Default Windows firewall log path
# ---------------------------------------------------------------------------
DEFAULT_WINDOWS_FW_LOG = Path(
    r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
)

# ---------------------------------------------------------------------------
# Global capture state — one capture session at a time
# ---------------------------------------------------------------------------
_capture_state: Dict[str, Any] = {
    "running": False,
    "engine": None,
    "interface": None,
    "started_at": None,
    "packets": deque(maxlen=10000),
    "stop_event": None,
    "thread": None,
}

_fw_monitor_state: Dict[str, Any] = {
    "running": False,
    "log_path": None,
    "lines_processed": 0,
    "alerts_generated": 0,
    "stop_event": None,
    "thread": None,
    "loop": None,
}


def set_background_event_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Store FastAPI's running event loop for background thread callbacks."""
    _fw_monitor_state["loop"] = loop


# ---------------------------------------------------------------------------
# Availability checks
# ---------------------------------------------------------------------------

def _scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except ImportError:
        return False


def _scapy_capture_ready() -> bool:
    """Return True only when Scapy has a packet capture provider available."""
    try:
        from scapy.all import conf

        if getattr(conf, "use_pcap", False):
            return True
        if platform.system().lower() == "windows":
            return False

        # On Windows, Scapy can import without Npcap/WinPcap, but sniffing at
        # layer 2 still fails immediately. L2listen is the path sniff() uses.
        return conf.L2listen is not None
    except Exception:
        return False


def _tshark_available() -> bool:
    try:
        result = subprocess.run(
            ["tshark", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _normalize_bpf_filter(value: Optional[str]) -> Optional[str]:
    """Treat UI placeholders as no filter instead of passing invalid BPF."""
    if value is None:
        return None
    normalized = value.strip()
    if not normalized or normalized.lower() in {"string", "none", "null"}:
        return None
    return normalized


def get_network_interfaces() -> List[NetworkInterface]:
    """
    Return available network interfaces.
    Tries Scapy first, falls back to socket-based discovery.
    """
    interfaces: List[NetworkInterface] = []

    if _scapy_available():
        try:
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            for i, iface in enumerate(ifaces):
                interfaces.append(NetworkInterface(
                    index=i,
                    name=iface.get("name", f"iface_{i}"),
                    description=iface.get("description", ""),
                    ip_addresses=[
                        addr for addr in iface.get("ips", [])
                        if addr and addr != "0.0.0.0"
                    ],
                    is_up=True,
                ))
            if interfaces:
                return interfaces
        except Exception as exc:
            logger.warning("Scapy interface discovery failed: {}", exc)

    # Fallback: use psutil if available
    try:
        import psutil
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for i, (name, addr_list) in enumerate(addrs.items()):
            ips = [
                a.address for a in addr_list
                if hasattr(a, "address") and "." in a.address
            ]
            is_up = stats.get(name, None)
            interfaces.append(NetworkInterface(
                index=i,
                name=name,
                description=name,
                ip_addresses=ips,
                is_up=is_up.isup if is_up else True,
            ))
        return interfaces
    except ImportError:
        pass

    # Minimal fallback
    return [NetworkInterface(
        index=0,
        name="Ethernet",
        description="Default network interface",
        ip_addresses=[],
    )]


# ---------------------------------------------------------------------------
# Scapy capture thread
# ---------------------------------------------------------------------------

def _scapy_capture_thread(
    interface_name: str,
    packet_limit: int,
    timeout_seconds: int,
    bpf_filter: Optional[str],
    stop_event: threading.Event,
    registry: ModelRegistry,
) -> None:
    """
    Runs in a background thread.
    Captures live packets using Scapy and runs ML classification on each flow.
    """
    try:
        from scapy.all import sniff, IP, TCP, UDP, Raw

        def _process_packet(pkt):
            if stop_event.is_set():
                return

            if not pkt.haslayer(IP):
                return

            ip = pkt[IP]
            flow: Dict[str, Any] = {
                "packet_id": str(uuid.uuid4())[:8],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "pkt_size": len(pkt),
                "protocol": "OTHER",
                "src_port": None,
                "dst_port": None,
                "prediction": "Pending",
                "confidence": 0.0,
                "threat_score": 0.0,
                "features_extracted": 0,
            }

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                flow["protocol"] = "TCP"
                flow["src_port"] = tcp.sport
                flow["dst_port"] = tcp.dport
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                flow["protocol"] = "UDP"
                flow["src_port"] = udp.sport
                flow["dst_port"] = udp.dport

            features = _extract_scapy_features(pkt, flow)
            _classify_store_and_score_flow(flow, features, registry)

        logger.info(
            "Scapy capture starting — interface={} limit={} timeout={}s filter={}",
            interface_name, packet_limit, timeout_seconds, bpf_filter or "none"
        )

        sniff(
            iface=interface_name,
            prn=_process_packet,
            count=packet_limit,
            timeout=timeout_seconds,
            filter=bpf_filter or "",
            store=False,
            stop_filter=lambda _: stop_event.is_set(),
        )

    except PermissionError:
        logger.error(
            "Scapy capture failed: permission denied. "
            "Run the backend as Administrator and install Npcap from https://npcap.com"
        )
    except Exception as exc:
        logger.error("Scapy capture thread error: {}", exc)
    finally:
        _capture_state["running"] = False
        logger.info("Scapy capture thread stopped.")


def _extract_scapy_features(pkt, flow: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract CICIDS2017-compatible features from a single Scapy packet.
    Single-packet flows are inherently low-coverage — the classifier
    will return Insufficient Evidence for most, which is correct behaviour.
    For better coverage use CICFlowMeter on a PCAP file.
    """
    from scapy.all import IP, TCP, UDP

    size = len(pkt)
    features: Dict[str, Any] = {
        "Total Fwd Packets": 1,
        "Total Backward Packets": 0,
        "Total Length of Fwd Packets": size,
        "Total Length of Bwd Packets": 0,
        "Fwd Packet Length Mean": float(size),
        "Bwd Packet Length Mean": 0.0,
        "Packet Length Mean": float(size),
        "Average Packet Size": float(size),
        "Avg Fwd Segment Size": float(size),
        "Avg Bwd Segment Size": 0.0,
        "Flow Duration": 0.0,
        "Flow Bytes/s": 0.0,
        "Flow Packets/s": 0.0,
        "Fwd Packets/s": 0.0,
        "Bwd Packets/s": 0.0,
        # TCP flags — all zero unless TCP layer present
        "FIN Flag Count": 0,
        "SYN Flag Count": 0,
        "RST Flag Count": 0,
        "PSH Flag Count": 0,
        "ACK Flag Count": 0,
        "URG Flag Count": 0,
        "Fwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "Init_Win_bytes_forward": 0,
        "Init_Win_bytes_backward": 0,
        "Flow IAT Mean": 0.0,
        "Flow IAT Std": 0.0,
        "Fwd IAT Mean": 0.0,
        "Bwd IAT Mean": 0.0,
        "Active Mean": 0.0,
        "Idle Mean": 0.0,
        "Packet Length Std": 0.0,
        # Metadata (not fed to ML)
        "src_ip": flow.get("src_ip"),
        "dst_ip": flow.get("dst_ip"),
        "dst_port": flow.get("dst_port"),
        "protocol": flow.get("protocol"),
    }

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = int(tcp.flags)
        features["FIN Flag Count"] = int(bool(flags & 0x01))
        features["SYN Flag Count"] = int(bool(flags & 0x02))
        features["RST Flag Count"] = int(bool(flags & 0x04))
        features["PSH Flag Count"] = int(bool(flags & 0x08))
        features["ACK Flag Count"] = int(bool(flags & 0x10))
        features["URG Flag Count"] = int(bool(flags & 0x20))
        features["Fwd PSH Flags"] = features["PSH Flag Count"]
        features["Fwd URG Flags"] = features["URG Flag Count"]
        features["Init_Win_bytes_forward"] = int(tcp.window)

    return features


# ---------------------------------------------------------------------------
# TShark capture thread
# ---------------------------------------------------------------------------

def _tshark_capture_thread(
    interface_name: str,
    packet_limit: int,
    timeout_seconds: int,
    bpf_filter: Optional[str],
    stop_event: threading.Event,
    registry: ModelRegistry,
) -> None:
    """Runs TShark as a subprocess and parses one packet per output line."""
    cmd = [
        "tshark",
        "-l",
        "-i", interface_name,
        "-c", str(packet_limit),
        "-a", f"duration:{timeout_seconds}",
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "frame.len",
        "-e", "ip.proto",
        "-e", "tcp.flags",
        "-e", "tcp.window_size",
        "-e", "_ws.col.Protocol",
    ]
    if bpf_filter:
        cmd += ["-f", bpf_filter]

    logger.info("TShark capture starting: {}", " ".join(cmd))
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for line in proc.stdout:
            if stop_event.is_set():
                proc.terminate()
                break
            flow, features = _parse_tshark_fields(line)
            if flow:
                _classify_store_and_score_flow(flow, features, registry)

    except FileNotFoundError:
        logger.error(
            "TShark not found. Install Wireshark from https://www.wireshark.org "
            "and ensure TShark is in your PATH."
        )
    except Exception as exc:
        logger.error("TShark capture error: {}", exc)
    finally:
        _capture_state["running"] = False
        logger.info("TShark capture thread stopped.")


def _parse_tshark_fields(line: str) -> tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """Parse one TShark fields line into display metadata and ML features."""
    try:
        parts = line.rstrip("\n").split("\t")
        while len(parts) < 11:
            parts.append("")
        (
            src_ip,
            dst_ip,
            tcp_src,
            tcp_dst,
            udp_src,
            udp_dst,
            frame_len,
            ip_proto,
            tcp_flags,
            tcp_window,
            ws_protocol,
        ) = parts[:11]

        if not src_ip or not dst_ip:
            return None, {}

        proto = (ws_protocol or _ip_protocol_name(ip_proto) or "OTHER").upper()
        src_port = _optional_int(tcp_src or udp_src)
        dst_port = _optional_int(tcp_dst or udp_dst)
        pkt_size = _optional_int(frame_len) or 0

        flow = {
            "packet_id": str(uuid.uuid4())[:8],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "pkt_size": pkt_size,
            "prediction": "Insufficient Evidence",
            "confidence": 0.0,
            "threat_score": 0.0,
            "features_extracted": 0,
        }
        flags = _parse_int(tcp_flags)
        features = _single_packet_features(
            size=pkt_size,
            flow=flow,
            tcp_flags=flags,
            tcp_window=_parse_int(tcp_window) or 0,
        )
        return flow, features
    except Exception:
        return None, {}


def _optional_int(value: object) -> Optional[int]:
    try:
        raw = str(value).strip()
        return int(raw) if raw else None
    except (TypeError, ValueError):
        return None


def _parse_int(value: object) -> Optional[int]:
    try:
        raw = str(value).strip()
        if not raw:
            return None
        return int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    except (TypeError, ValueError):
        return None


def _ip_protocol_name(value: str) -> str | None:
    return {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(str(value).strip())


def _classify_store_and_score_flow(
    flow: Dict[str, Any],
    features: Dict[str, Any],
    registry: ModelRegistry,
) -> None:
    """Classify a live packet/flow, keep it in memory, persist it, and score risky IPs."""
    feature_coverage = 0.0
    if registry.packet_classifier_available:
        try:
            df = pd.DataFrame([features])
            result = registry.packet_classifier.predict(df)
            row = result.iloc[0]
            prediction = str(row.get("prediction", "Insufficient Evidence"))
            confidence = _float(row.get("confidence"), default=0.0)
            feature_coverage = _float(row.get("feature_coverage"), default=0.0)
            threat_score = _float(
                row.get("threat_score_contribution"),
                default=_packet_score(prediction, confidence),
            )
            if str(row.get("traffic_schema", "")) == "insufficient-live-flow-features":
                prediction = "Insufficient Evidence"
                confidence = 0.0
                threat_score = 0.0
            flow["prediction"] = prediction
            flow["confidence"] = confidence
            flow["threat_score"] = threat_score
            flow["features_extracted"] = int(round(feature_coverage * 32))
        except Exception as exc:
            logger.debug("Packet classification error: {}", exc)
            flow["prediction"] = "Insufficient Evidence"

    _capture_state["packets"].append(flow)
    _schedule_packet_persist(flow, feature_coverage)


def _single_packet_features(
    size: int,
    flow: Dict[str, Any],
    tcp_flags: int = 0,
    tcp_window: int = 0,
) -> Dict[str, Any]:
    return {
        "Total Fwd Packets": 1,
        "Total Backward Packets": 0,
        "Total Length of Fwd Packets": size,
        "Total Length of Bwd Packets": 0,
        "Fwd Packet Length Mean": float(size),
        "Bwd Packet Length Mean": 0.0,
        "Packet Length Mean": float(size),
        "Average Packet Size": float(size),
        "Avg Fwd Segment Size": float(size),
        "Avg Bwd Segment Size": 0.0,
        "Flow Duration": 0.0,
        "Flow Bytes/s": 0.0,
        "Flow Packets/s": 0.0,
        "Fwd Packets/s": 0.0,
        "Bwd Packets/s": 0.0,
        "FIN Flag Count": int(bool(tcp_flags & 0x01)),
        "SYN Flag Count": int(bool(tcp_flags & 0x02)),
        "RST Flag Count": int(bool(tcp_flags & 0x04)),
        "PSH Flag Count": int(bool(tcp_flags & 0x08)),
        "ACK Flag Count": int(bool(tcp_flags & 0x10)),
        "URG Flag Count": int(bool(tcp_flags & 0x20)),
        "Fwd PSH Flags": int(bool(tcp_flags & 0x08)),
        "Fwd URG Flags": int(bool(tcp_flags & 0x20)),
        "Init_Win_bytes_forward": tcp_window,
        "Init_Win_bytes_backward": 0,
        "Flow IAT Mean": 0.0,
        "Flow IAT Std": 0.0,
        "Fwd IAT Mean": 0.0,
        "Bwd IAT Mean": 0.0,
        "Active Mean": 0.0,
        "Idle Mean": 0.0,
        "Packet Length Std": 0.0,
        "src_ip": flow.get("src_ip"),
        "dst_ip": flow.get("dst_ip"),
        "dst_port": flow.get("dst_port"),
        "protocol": flow.get("protocol"),
    }


def _schedule_packet_persist(flow: Dict[str, Any], feature_coverage: float) -> None:
    loop = _fw_monitor_state.get("loop")
    if loop is None or not loop.is_running():
        logger.warning("Skipping packet persistence: application event loop is unavailable")
        return

    future = asyncio.run_coroutine_threadsafe(_persist_packet_event(flow, feature_coverage), loop)
    future.add_done_callback(_log_background_failure)


async def _persist_packet_event(flow: Dict[str, Any], feature_coverage: float) -> None:
    async with AsyncSessionLocal() as session:
        try:
            event = PacketEvent(
                timestamp=flow.get("timestamp"),
                src_ip=flow.get("src_ip"),
                dst_ip=flow.get("dst_ip"),
                dst_port=flow.get("dst_port"),
                protocol=flow.get("protocol"),
                prediction=flow.get("prediction") or "Insufficient Evidence",
                confidence=float(flow.get("confidence") or 0.0),
                feature_coverage=feature_coverage,
                missing_feature_count=max(0, 32 - int(flow.get("features_extracted") or 0)),
                traffic_schema="live-capture-single-packet",
                threat_score_contribution=float(flow.get("threat_score") or 0.0),
                source="realtime",
            )
            session.add(event)
            if _should_score_packet(flow):
                await ThreatScoringService(db=session).score(
                    str(flow.get("src_ip")),
                    {"source": "live_packet_capture", "packet_id": flow.get("packet_id")},
                )
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def _should_score_packet(flow: Dict[str, Any]) -> bool:
    return bool(
        flow.get("src_ip")
        and (
            flow.get("prediction") in {"Suspicious", "Malicious"}
            or float(flow.get("threat_score") or 0.0) >= 25.0
        )
    )


def _log_background_failure(future: asyncio.Future) -> None:
    try:
        future.result()
    except Exception as exc:
        logger.warning("Background packet persistence/scoring failed: {}", exc)


def _float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _packet_score(prediction: str, confidence: float) -> float:
    base = {"Normal": 0.0, "Suspicious": 50.0, "Malicious": 85.0}.get(prediction, 0.0)
    return round(max(0.0, min(100.0, base * max(0.0, min(confidence, 1.0)))), 2)


# ---------------------------------------------------------------------------
# Windows Firewall real-time monitor thread
# ---------------------------------------------------------------------------

def _firewall_monitor_thread(
    log_path: Path,
    poll_interval: int,
    stop_event: threading.Event,
    registry: ModelRegistry,
) -> None:
    """
    Tails pfirewall.log and feeds new lines into the unsupervised pipeline.
    Runs in a background thread.
    """
    logger.info("Firewall monitor starting: path={}", log_path)

    if not log_path.exists():
        logger.error(
            "Firewall log not found: {}. "
            "Enable Windows Firewall logging: "
            "Control Panel → Windows Defender Firewall → Advanced Settings → "
            "Properties → Logging → Log dropped/successful connections.",
            log_path,
        )
        _fw_monitor_state["running"] = False
        return

    # Seek to end of file — only process NEW lines from now on
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)  # seek to end
            current_pos = f.tell()
    except PermissionError:
        logger.error(
            "Permission denied reading {}. Run backend as Administrator.", log_path
        )
        _fw_monitor_state["running"] = False
        return

    logger.info("Firewall monitor ready — watching for new entries...")

    while not stop_event.is_set():
        time.sleep(poll_interval)
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(current_pos)
                new_lines = f.readlines()
                current_pos = f.tell()

            for line in new_lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                _fw_monitor_state["lines_processed"] += 1
                _process_firewall_line(line, registry)

        except Exception as exc:
            logger.warning("Firewall monitor read error: {}", exc)

    _fw_monitor_state["running"] = False
    logger.info("Firewall monitor stopped.")


def _process_firewall_line(line: str, registry: ModelRegistry) -> None:
    """
    Parse one pfirewall.log line and feed it into the unsupervised pipeline.

    pfirewall.log format:
    date time action protocol src-ip dst-ip src-port dst-port size ...
    e.g.: 2026-06-12 14:01:05 DROP TCP 10.0.0.5 192.168.1.99 51515 22 64 ...
    """
    try:
        parts = line.split()
        if len(parts) < 9:
            return

        date_str, time_str = parts[0], parts[1]
        action = parts[2].upper()
        protocol = parts[3].upper()
        src_ip = parts[4]
        dst_ip = parts[5]
        src_port = parts[6]
        dst_port_str = parts[7]
        pkt_size = parts[8]

        if src_ip == "-" or dst_ip == "-":
            return

        event = {
            "timestamp": f"{date_str} {time_str}",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": int(dst_port_str) if dst_port_str.isdigit() else 0,
            "protocol": protocol,
            "pkt_size": int(pkt_size) if pkt_size.isdigit() else 400,
            "action": action,
            "is_block": 1 if action in ("DROP", "DENY", "BLOCK") else 0,
        }

        if registry.firewall_pipeline_available:
            results = registry.firewall_pipeline.ingest_realtime(event)
            signals = results.get("threat_signals", [])
            if signals:
                _fw_monitor_state["alerts_generated"] += len(signals)
                for sig in signals:
                    signal_ip = sig.get("src_ip")
                    logger.warning(
                        "Firewall alert: IP={} severity={} score={}",
                        signal_ip,
                        sig.get("severity"),
                        sig.get("threat_score"),
                    )
                    if signal_ip:
                        _schedule_unified_score(str(signal_ip), sig)

    except Exception as exc:
        logger.debug("Could not parse firewall line: {} - {}", line[:80], exc)


def _schedule_unified_score(ip: str, evidence: Dict[str, Any]) -> None:
    """Schedule unified scoring on the FastAPI event loop from this thread."""
    loop = _fw_monitor_state.get("loop")
    if loop is None or not loop.is_running():
        logger.warning("Skipping unified scoring for {}: application event loop is unavailable", ip)
        return

    future = asyncio.run_coroutine_threadsafe(_score_firewall_signal(ip, evidence), loop)
    try:
        future.result(timeout=30)
    except Exception as exc:
        logger.warning("Unified scoring failed for {}: {}", ip, exc)


async def _score_firewall_signal(ip: str, evidence: Dict[str, Any]) -> None:
    """Open a background DB session and log the unified score for a signal."""
    async with AsyncSessionLocal() as session:
        try:
            score = await ThreatScoringService(db=session).score(ip, evidence)
            await session.commit()
            logger.warning(
                "Unified threat score for {ip}: {score} ({severity})",
                ip=ip,
                score=score.final_score,
                severity=score.severity,
            )
        except Exception:
            await session.rollback()
            raise


# ---------------------------------------------------------------------------
# PacketCaptureService — called by router
# ---------------------------------------------------------------------------

class PacketCaptureService:
    def __init__(self, registry: ModelRegistry, db: AsyncSession):
        self.registry = registry
        self.db = db

    # ------------------------------------------------------------------
    # Interfaces
    # ------------------------------------------------------------------

    def list_interfaces(self):
        return (
            get_network_interfaces(),
            _scapy_capture_ready(),
            _tshark_available(),
        )

    # ------------------------------------------------------------------
    # Packet capture
    # ------------------------------------------------------------------

    async def start_capture(self, req: CaptureStartRequest) -> CaptureStatusResponse:
        if _capture_state["running"]:
            return CaptureStatusResponse(
                is_running=True,
                engine=_capture_state["engine"],
                interface=_capture_state["interface"],
                packets_captured=len(_capture_state["packets"]),
                message="Capture already running. Stop it first.",
            )

        # Resolve interface name
        interfaces = get_network_interfaces()
        if req.interface_index >= len(interfaces):
            return CaptureStatusResponse(
                success=False,
                is_running=False,
                message=f"Interface index {req.interface_index} not found. "
                        f"Available: 0–{len(interfaces)-1}",
            )
        iface = interfaces[req.interface_index]

        bpf_filter = _normalize_bpf_filter(req.bpf_filter)

        # Choose engine. Scapy importing is not enough on Windows; sniff()
        # needs Npcap/WinPcap/libpcap available, otherwise the thread dies.
        scapy_ready = _scapy_capture_ready()
        tshark_ready = _tshark_available()
        use_tshark = req.use_tshark or not scapy_ready

        if use_tshark and not tshark_ready:
            return CaptureStatusResponse(
                success=False,
                is_running=False,
                message=(
                    "Packet capture is unavailable: Scapy cannot access a "
                    "libpcap/Npcap provider and TShark was not found. Install "
                    "Npcap from https://npcap.com, or install Wireshark and "
                    "enable use_tshark=true."
                ),
            )

        engine = "tshark" if use_tshark else "scapy"
        stop_event = threading.Event()
        _capture_state.update({
            "running": True,
            "engine": engine,
            "interface": iface.name,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "stop_event": stop_event,
        })
        _capture_state["packets"].clear()

        target_fn = _tshark_capture_thread if use_tshark else _scapy_capture_thread
        thread = threading.Thread(
            target=target_fn,
            args=(
                iface.name,
                req.packet_limit,
                req.timeout_seconds,
                bpf_filter,
                stop_event,
                self.registry,
            ),
            daemon=True,
        )
        _capture_state["thread"] = thread
        thread.start()

        logger.info("Started {} capture on interface '{}'", engine, iface.name)
        return CaptureStatusResponse(
            is_running=True,
            engine=engine,
            interface=iface.name,
            packets_captured=0,
            started_at=_capture_state["started_at"],
            message=f"{engine.upper()} capture started on '{iface.name}'.",
        )

    async def stop_capture(self) -> CaptureStatusResponse:
        if not _capture_state["running"]:
            return CaptureStatusResponse(
                is_running=False,
                packets_captured=len(_capture_state["packets"]),
                message="No capture is running.",
            )

        stop_event: threading.Event = _capture_state.get("stop_event")
        if stop_event:
            stop_event.set()

        _capture_state["running"] = False
        count = len(_capture_state["packets"])
        logger.info("Capture stopped. {} packets captured.", count)

        return CaptureStatusResponse(
            is_running=False,
            engine=_capture_state.get("engine"),
            interface=_capture_state.get("interface"),
            packets_captured=count,
            started_at=_capture_state.get("started_at"),
            message=f"Capture stopped. {count} packets captured.",
        )

    async def get_status(self) -> CaptureStatusResponse:
        packets = list(_capture_state["packets"])
        classified = [p for p in packets if p["prediction"] != "Pending"]
        return CaptureStatusResponse(
            is_running=_capture_state["running"],
            engine=_capture_state.get("engine"),
            interface=_capture_state.get("interface"),
            packets_captured=len(packets),
            packets_classified=len(classified),
            started_at=_capture_state.get("started_at"),
            message="Capture running." if _capture_state["running"] else "Capture stopped.",
        )

    async def get_packets(self) -> CapturedPacketsResponse:
        packets = list(_capture_state["packets"])
        results = [CapturedPacketResult(**p) for p in packets]

        normal = sum(1 for r in results if r.prediction == "Normal")
        suspicious = sum(1 for r in results if r.prediction == "Suspicious")
        malicious = sum(1 for r in results if r.prediction == "Malicious")
        scores = [r.threat_score for r in results if r.threat_score > 0]

        return CapturedPacketsResponse(
            total=len(results),
            packets=results,
            normal_count=normal,
            suspicious_count=suspicious,
            malicious_count=malicious,
            avg_threat_score=round(sum(scores) / len(scores), 2) if scores else 0.0,
        )

    # ------------------------------------------------------------------
    # Firewall monitor
    # ------------------------------------------------------------------

    async def start_firewall_monitor(self, req: FirewallMonitorRequest) -> FirewallMonitorResponse:
        self.registry.require_firewall_pipeline()
        set_background_event_loop(asyncio.get_running_loop())

        if _fw_monitor_state["running"]:
            return FirewallMonitorResponse(
                is_running=True,
                log_path=str(_fw_monitor_state["log_path"]),
                lines_processed=_fw_monitor_state["lines_processed"],
                alerts_generated=_fw_monitor_state["alerts_generated"],
                message="Firewall monitor already running.",
            )

        log_path = Path(req.log_path) if req.log_path else DEFAULT_WINDOWS_FW_LOG
        stop_event = threading.Event()

        _fw_monitor_state.update({
            "running": True,
            "log_path": log_path,
            "lines_processed": 0,
            "alerts_generated": 0,
            "stop_event": stop_event,
        })

        thread = threading.Thread(
            target=_firewall_monitor_thread,
            args=(log_path, req.poll_interval_seconds, stop_event, self.registry),
            daemon=True,
        )
        _fw_monitor_state["thread"] = thread
        thread.start()

        return FirewallMonitorResponse(
            is_running=True,
            log_path=str(log_path),
            message=f"Firewall monitor started — watching {log_path}",
        )

    async def stop_firewall_monitor(self) -> FirewallMonitorResponse:
        if not _fw_monitor_state["running"]:
            return FirewallMonitorResponse(
                is_running=False,
                log_path=str(_fw_monitor_state.get("log_path", "")),
                lines_processed=_fw_monitor_state["lines_processed"],
                alerts_generated=_fw_monitor_state["alerts_generated"],
                message="Firewall monitor is not running.",
            )

        stop_event: threading.Event = _fw_monitor_state.get("stop_event")
        if stop_event:
            stop_event.set()

        _fw_monitor_state["running"] = False
        return FirewallMonitorResponse(
            is_running=False,
            log_path=str(_fw_monitor_state.get("log_path", "")),
            lines_processed=_fw_monitor_state["lines_processed"],
            alerts_generated=_fw_monitor_state["alerts_generated"],
            message="Firewall monitor stopped.",
        )

    async def get_firewall_monitor_status(self) -> FirewallMonitorResponse:
        return FirewallMonitorResponse(
            is_running=_fw_monitor_state["running"],
            log_path=str(_fw_monitor_state.get("log_path", "")),
            lines_processed=_fw_monitor_state["lines_processed"],
            alerts_generated=_fw_monitor_state["alerts_generated"],
            message="Monitor running." if _fw_monitor_state["running"] else "Monitor stopped.",
        )
