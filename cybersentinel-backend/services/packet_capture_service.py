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

from core.config import settings
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
from services.live_flow_processor import LiveFlowProcessor, LiveFlowState
from services.packet_service import PacketService
from services.threat_scoring_service import ThreatScoringService

# ---------------------------------------------------------------------------
# Default Windows firewall log path
# ---------------------------------------------------------------------------
DEFAULT_WINDOWS_FW_LOG = Path(
    r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
)

# ---------------------------------------------------------------------------
# Per-user capture / monitor state (isolated by authenticated user_id)
# ---------------------------------------------------------------------------
_app_event_loop: asyncio.AbstractEventLoop | None = None
_capture_sessions: Dict[str, Dict[str, Any]] = {}
_fw_monitor_sessions: Dict[str, Dict[str, Any]] = {}


def _new_capture_state() -> Dict[str, Any]:
    return {
        "running": False,
        "engine": None,
        "interface": None,
        "started_at": None,
        "packets": deque(maxlen=10000),
        "stop_event": None,
        "thread": None,
        "flow_processor": None,
    }


def _new_fw_monitor_state() -> Dict[str, Any]:
    return {
        "running": False,
        "log_path": None,
        "lines_processed": 0,
        "alerts_generated": 0,
        "stop_event": None,
        "thread": None,
    }


def _capture_state_for(user_id: str) -> Dict[str, Any]:
    if user_id not in _capture_sessions:
        _capture_sessions[user_id] = _new_capture_state()
    return _capture_sessions[user_id]


def _fw_monitor_state_for(user_id: str) -> Dict[str, Any]:
    if user_id not in _fw_monitor_sessions:
        _fw_monitor_sessions[user_id] = _new_fw_monitor_state()
    return _fw_monitor_sessions[user_id]


def set_background_event_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Store FastAPI's running event loop for background thread callbacks."""
    global _app_event_loop
    _app_event_loop = loop


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


def _is_routable_ipv4(address: str) -> bool:
    """True for normal LAN/WAN IPv4 addresses (not loopback or link-local)."""
    if not address or "." not in address:
        return False
    if address.startswith(("127.", "169.254.")) or address == "0.0.0.0":
        return False
    parts = address.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _filter_routable_ips(ips: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for raw in ips:
        ip = str(raw).strip()
        if _is_routable_ipv4(ip) and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _psutil_interface_maps() -> tuple[Dict[str, bool], Dict[str, List[str]]]:
    try:
        import psutil

        up_map = {name: stat.isup for name, stat in psutil.net_if_stats().items()}
        ip_map: Dict[str, List[str]] = {}
        for name, addr_list in psutil.net_if_addrs().items():
            ip_map[name] = _filter_routable_ips(
                [a.address for a in addr_list if getattr(a, "address", None)]
            )
        return up_map, ip_map
    except Exception:
        return {}, {}


def _match_psutil_iface(description: str, psutil_names: List[str]) -> str | None:
    """Match a Scapy/Npcap description to a psutil interface name."""
    desc = description.lower().replace("–", "-")
    for pname in psutil_names:
        pl = pname.lower().replace("–", "-")
        if pl == desc or pl in desc or desc in pl:
            return pname
    wifi_tokens = ("wi-fi", "wifi", "wlan", "wireless")
    eth_tokens = ("ethernet", "eth ")
    if any(t in desc for t in wifi_tokens):
        for pname in psutil_names:
            pl = pname.lower()
            if any(t in pl for t in wifi_tokens):
                return pname
    if any(t in desc for t in eth_tokens):
        for pname in psutil_names:
            pl = pname.lower()
            if "ethernet" in pl or pl.startswith("eth"):
                return pname
    return None


def pick_default_interface_index(interfaces: List[NetworkInterface]) -> int | None:
    """Pick the interface that is actually connected (has routable IP, link up)."""
    best_index: int | None = None
    best_score = -10_000

    for iface in interfaces:
        score = _score_interface_candidate(iface)
        if score > best_score:
            best_score = score
            best_index = iface.index

    return best_index if best_score >= 0 else None


def _score_interface_candidate(iface: NetworkInterface) -> int:
    ips = _filter_routable_ips(iface.ip_addresses)
    if not ips:
        return -1000
    if not iface.is_up:
        return -900

    label = f"{iface.name} {iface.description}".lower()
    score = 1000

    if "loopback" in label or iface.name.lower() in {"lo", "loopback"}:
        return -2000
    if any(
        token in label
        for token in ("virtual", "vmware", "vethernet", "hyper-v", "bluetooth", "npcap loopback")
    ):
        score -= 200

    # Small tie-breaker only among connected interfaces.
    if any(t in label for t in ("ethernet", "eth ")) or label.strip().startswith("eth"):
        score += 5
    if any(t in label for t in ("wi-fi", "wifi", "wlan", "wireless")):
        score += 3

    return score


def get_network_interfaces() -> List[NetworkInterface]:
    """
    Return available network interfaces.
    Tries Scapy first, falls back to socket-based discovery.
    """
    interfaces: List[NetworkInterface] = []
    psutil_up, psutil_ips = _psutil_interface_maps()

    if _scapy_available():
        try:
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            for i, iface in enumerate(ifaces):
                name = iface.get("name", f"iface_{i}")
                description = iface.get("description", "") or ""
                ips = _filter_routable_ips(iface.get("ips", []))

                matched = _match_psutil_iface(description, list(psutil_up.keys()))
                if matched:
                    ips = list(dict.fromkeys(ips + psutil_ips.get(matched, [])))
                    is_up = bool(ips) and psutil_up.get(matched, False)
                else:
                    is_up = bool(ips)

                interfaces.append(NetworkInterface(
                    index=i,
                    name=name,
                    description=description,
                    ip_addresses=ips,
                    is_up=is_up,
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
            ips = _filter_routable_ips(
                [a.address for a in addr_list if hasattr(a, "address", None)]
            )
            stat = stats.get(name)
            is_up = bool(stat.isup if stat else False) and bool(ips)
            interfaces.append(NetworkInterface(
                index=i,
                name=name,
                description=name,
                ip_addresses=ips,
                is_up=is_up,
            ))
        return interfaces
    except ImportError:
        pass

    # Minimal fallback
    return [NetworkInterface(
        index=0,
        name="Wifi",
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
    user_id: str,
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

            flags = None
            if pkt.haslayer(TCP):
                flags = _tcp_flags_from_int(int(pkt[TCP].flags))
            _ingest_live_packet(
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=flow.get("src_port"),
                dst_port=flow.get("dst_port"),
                protocol=str(flow.get("protocol") or "OTHER"),
                packet_size=len(pkt),
                flags=flags,
                registry=registry,
                user_id=user_id,
            )

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
        _capture_state_for(user_id)["running"] = False
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
    user_id: str,
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
            flow, meta = _parse_tshark_fields(line)
            if meta:
                _ingest_live_packet(
                    src_ip=meta["src_ip"],
                    dst_ip=meta["dst_ip"],
                    src_port=meta.get("src_port"),
                    dst_port=meta.get("dst_port"),
                    protocol=meta.get("protocol", "OTHER"),
                    packet_size=meta.get("pkt_size", 0),
                    flags=meta.get("flags"),
                    registry=registry,
                    user_id=user_id,
                )

    except FileNotFoundError:
        logger.error(
            "TShark not found. Install Wireshark from https://www.wireshark.org "
            "and ensure TShark is in your PATH."
        )
    except Exception as exc:
        logger.error("TShark capture error: {}", exc)
    finally:
        _capture_state_for(user_id)["running"] = False
        logger.info("TShark capture thread stopped.")


def _parse_tshark_fields(line: str) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Parse one TShark fields line into packet metadata for flow aggregation."""
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
            _tcp_window,
            ws_protocol,
        ) = parts[:11]

        if not src_ip or not dst_ip:
            return None, None

        proto = (ws_protocol or _ip_protocol_name(ip_proto) or "OTHER").upper()
        src_port = _optional_int(tcp_src or udp_src)
        dst_port = _optional_int(tcp_dst or udp_dst)
        pkt_size = _optional_int(frame_len) or 0
        flags_int = _parse_int(tcp_flags)
        flags = _tcp_flags_from_int(flags_int) if flags_int is not None else None

        return None, {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "pkt_size": pkt_size,
            "flags": flags,
        }
    except Exception:
        return None, None


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


def _tcp_flags_from_int(flags: int) -> dict[str, bool]:
    return {
        "SYN": bool(flags & 0x02),
        "ACK": bool(flags & 0x10),
        "FIN": bool(flags & 0x01),
        "RST": bool(flags & 0x04),
        "PSH": bool(flags & 0x08),
        "URG": bool(flags & 0x20),
    }


def _ingest_live_packet(
    *,
    src_ip: str,
    dst_ip: str,
    src_port: int | None,
    dst_port: int | None,
    protocol: str,
    packet_size: int,
    flags: dict[str, bool] | None,
    registry: ModelRegistry,
    user_id: str,
) -> None:
    """Aggregate packets into bidirectional flows; classify on flow completion."""
    processor: LiveFlowProcessor | None = _capture_state_for(user_id).get("flow_processor")
    if processor is None:
        return
    processor.ingest(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_size=packet_size,
        flags=flags,
    )
    for _ in processor.flush_expired():
        pass


def _schedule_flow_classification(
    flow_state: LiveFlowState,
    registry: ModelRegistry,
    user_id: str,
) -> None:
    loop = _app_event_loop
    if loop is None or not loop.is_running():
        logger.warning("Skipping flow classification: application event loop is unavailable")
        return
    future = asyncio.run_coroutine_threadsafe(
        _classify_and_store_flow(flow_state, registry, user_id),
        loop,
    )
    future.add_done_callback(_log_background_failure)


async def _classify_and_store_flow(
    flow_state: LiveFlowState,
    registry: ModelRegistry,
    user_id: str,
) -> None:
    """Run full hybrid SOC pipeline (XGBoost + IF + rules + fusion) on a completed flow."""
    if not registry.packet_classifier_available:
        return

    async with AsyncSessionLocal() as session:
        try:
            service = PacketService(registry=registry, db=session, user_id=user_id)
            response = await service.classify_single(flow_state.to_flow_features())
            result = response.result
            entry = {
                "packet_id": flow_state.flow_id,
                "timestamp": datetime.fromtimestamp(flow_state.last_seen, tz=timezone.utc).isoformat(),
                "src_ip": flow_state.fwd_ip,
                "dst_ip": flow_state.bwd_ip,
                "src_port": flow_state.fwd_port or None,
                "dst_port": flow_state.bwd_port or None,
                "protocol": flow_state.protocol,
                "pkt_size": flow_state.fwd_bytes + flow_state.bwd_bytes,
                "prediction": result.prediction,
                "confidence": result.final_confidence,
                "threat_score": result.risk_score,
                "features_extracted": int(round((result.feature_coverage or 0.0) * 23)),
                "source": "live_flow",
            }
            _capture_state_for(user_id)["packets"].append(entry)
            if _should_score_packet(entry):
                await ThreatScoringService(db=session, user_id=user_id).score(
                    str(flow_state.fwd_ip),
                    {
                        "source": "live_flow_capture",
                        "flow_id": flow_state.flow_id,
                        "prediction": result.prediction,
                        "risk_score": result.risk_score,
                    },
                )
            await session.commit()
            logger.info(
                "Live flow classified {} → {} → {} (risk={})",
                flow_state.flow_id,
                flow_state.fwd_ip,
                result.prediction,
                result.risk_score,
            )
        except Exception:
            await session.rollback()
            raise


def _classify_store_and_score_flow(
    flow: Dict[str, Any],
    features: Dict[str, Any],
    registry: ModelRegistry,
    model_type: str | None = None,
    *,
    user_id: str,
) -> None:
    """Classify a live packet/flow, keep it in memory, persist it, and score risky IPs."""
    feature_coverage = 0.0
    if registry.packet_classifier_available:
        try:
            classifier = registry.require_packet_classifier(model_type)
            df = pd.DataFrame([features])
            result = classifier.predict(df)
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

    _capture_state_for(user_id)["packets"].append(flow)
    _schedule_packet_persist(flow, feature_coverage, user_id)


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


def _schedule_packet_persist(flow: Dict[str, Any], feature_coverage: float, user_id: str) -> None:
    loop = _app_event_loop
    if loop is None or not loop.is_running():
        logger.warning("Skipping packet persistence: application event loop is unavailable")
        return

    future = asyncio.run_coroutine_threadsafe(
        _persist_packet_event(flow, feature_coverage, user_id),
        loop,
    )
    future.add_done_callback(_log_background_failure)


async def _persist_packet_event(flow: Dict[str, Any], feature_coverage: float, user_id: str) -> None:
    async with AsyncSessionLocal() as session:
        try:
            event = PacketEvent(
                user_id=user_id,
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
                source=flow.get("source") or "realtime",
            )
            session.add(event)
            if _should_score_packet(flow):
                await ThreatScoringService(db=session, user_id=user_id).score(
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
    user_id: str,
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
        _fw_monitor_state_for(user_id)["running"] = False
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
        _fw_monitor_state_for(user_id)["running"] = False
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
                _fw_monitor_state_for(user_id)["lines_processed"] += 1
                _process_firewall_line(line, registry, user_id)

        except Exception as exc:
            logger.warning("Firewall monitor read error: {}", exc)

    _fw_monitor_state_for(user_id)["running"] = False
    logger.info("Firewall monitor stopped.")


def _process_firewall_line(line: str, registry: ModelRegistry, user_id: str) -> None:
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
                _fw_monitor_state_for(user_id)["alerts_generated"] += len(signals)
                for sig in signals:
                    signal_ip = sig.get("src_ip")
                    logger.warning(
                        "Firewall alert: IP={} severity={} score={}",
                        signal_ip,
                        sig.get("severity"),
                        sig.get("threat_score"),
                    )
                    if signal_ip:
                        _schedule_unified_score(str(signal_ip), sig, user_id)

    except Exception as exc:
        logger.debug("Could not parse firewall line: {} - {}", line[:80], exc)


def _schedule_unified_score(ip: str, evidence: Dict[str, Any], user_id: str) -> None:
    """Schedule unified scoring on the FastAPI event loop from this thread."""
    loop = _app_event_loop
    if loop is None or not loop.is_running():
        logger.warning("Skipping unified scoring for {}: application event loop is unavailable", ip)
        return

    future = asyncio.run_coroutine_threadsafe(_score_firewall_signal(ip, evidence, user_id), loop)
    try:
        future.result(timeout=30)
    except Exception as exc:
        logger.warning("Unified scoring failed for {}: {}", ip, exc)


async def _score_firewall_signal(ip: str, evidence: Dict[str, Any], user_id: str) -> None:
    """Open a background DB session and log the unified score for a signal."""
    async with AsyncSessionLocal() as session:
        try:
            score = await ThreatScoringService(db=session, user_id=user_id).score(ip, evidence)
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
    def __init__(self, registry: ModelRegistry, db: AsyncSession, user_id: str):
        self.registry = registry
        self.db = db
        self.user_id = user_id

    def _capture_state(self) -> Dict[str, Any]:
        return _capture_state_for(self.user_id)

    def _fw_monitor_state(self) -> Dict[str, Any]:
        return _fw_monitor_state_for(self.user_id)

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
        state = self._capture_state()
        if state["running"]:
            return CaptureStatusResponse(
                is_running=True,
                engine=state["engine"],
                interface=state["interface"],
                packets_captured=len(state["packets"]),
                message="Capture already running. Stop it first.",
            )

        # Resolve interface — prefer a connected adapter (routable IP, link up).
        interfaces = get_network_interfaces()
        recommended = pick_default_interface_index(interfaces)
        idx = req.interface_index
        if recommended is not None:
            if idx >= len(interfaces) or not _filter_routable_ips(interfaces[idx].ip_addresses):
                idx = recommended
        elif idx >= len(interfaces):
            return CaptureStatusResponse(
                success=False,
                is_running=False,
                message="No connected network interface found for packet capture.",
            )

        if idx >= len(interfaces):
            return CaptureStatusResponse(
                success=False,
                is_running=False,
                message=f"Interface index {req.interface_index} not found. "
                        f"Available: 0–{len(interfaces)-1}",
            )
        iface = interfaces[idx]
        if not _filter_routable_ips(iface.ip_addresses):
            return CaptureStatusResponse(
                success=False,
                is_running=False,
                message=(
                    f"Interface '{iface.description or iface.name}' has no active IPv4 address. "
                    "Connect to Wi‑Fi or Ethernet and try again."
                ),
            )

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
        state.update({
            "running": True,
            "engine": engine,
            "interface": iface.name,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "stop_event": stop_event,
        })
        state["packets"].clear()

        def _on_flow_complete(flow: LiveFlowState) -> None:
            _schedule_flow_classification(flow, self.registry, self.user_id)

        state["flow_processor"] = LiveFlowProcessor(on_flow_complete=_on_flow_complete)

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
                self.user_id,
            ),
            daemon=True,
        )
        state["thread"] = thread
        thread.start()

        logger.info("Started {} capture on interface '{}'", engine, iface.name)
        return CaptureStatusResponse(
            is_running=True,
            engine=engine,
            interface=iface.name,
            packets_captured=0,
            started_at=state["started_at"],
            message=f"{engine.upper()} capture started on '{iface.name}'. Flows are aggregated before hybrid ML classification.",
        )

    async def stop_capture(self) -> CaptureStatusResponse:
        state = self._capture_state()
        if not state["running"]:
            return CaptureStatusResponse(
                is_running=False,
                packets_captured=len(state["packets"]),
                message="No capture is running.",
            )

        stop_event: threading.Event = state.get("stop_event")
        if stop_event:
            stop_event.set()

        processor: LiveFlowProcessor | None = state.get("flow_processor")
        if processor is not None:
            processor.flush_all()

        state["running"] = False
        count = len(state["packets"])
        logger.info("Capture stopped. {} flow(s) classified.", count)

        return CaptureStatusResponse(
            is_running=False,
            engine=state.get("engine"),
            interface=state.get("interface"),
            packets_captured=count,
            started_at=state.get("started_at"),
            message=f"Capture stopped. {count} flow(s) classified.",
        )

    async def get_status(self) -> CaptureStatusResponse:
        state = self._capture_state()
        packets = list(state["packets"])
        classified = [p for p in packets if p["prediction"] != "Pending"]
        return CaptureStatusResponse(
            is_running=state["running"],
            engine=state.get("engine"),
            interface=state.get("interface"),
            packets_captured=len(packets),
            packets_classified=len(classified),
            started_at=state.get("started_at"),
            message="Capture running." if state["running"] else "Capture stopped.",
        )

    async def get_packets(self) -> CapturedPacketsResponse:
        packets = list(self._capture_state()["packets"])
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

    async def import_pcap(
        self,
        file_bytes: bytes,
        model_type: str | None = None,
    ) -> CaptureStatusResponse:
        from scapy.all import IP, TCP, UDP
        from scapy.utils import PcapReader
        import io

        processor = LiveFlowProcessor()
        processed = 0
        reader = PcapReader(io.BytesIO(file_bytes))
        try:
            for pkt in reader:
                if processed >= settings.MAX_PCAP_PACKETS:
                    break
                if not hasattr(pkt, "haslayer") or not pkt.haslayer(IP):
                    continue
                ip = pkt[IP]
                src_port = None
                dst_port = None
                protocol = "OTHER"
                flags = None
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    protocol = "TCP"
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    flags = _tcp_flags_from_int(int(tcp.flags))
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    protocol = "UDP"
                    src_port = udp.sport
                    dst_port = udp.dport
                processor.ingest(
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    packet_size=len(pkt),
                    flags=flags,
                )
                processed += 1
        finally:
            reader.close()

        flows = processor.flush_all()
        for flow in flows:
            await _classify_and_store_flow(flow, self.registry, self.user_id)

        classified = len(self._capture_state()["packets"])
        return CaptureStatusResponse(
            success=True,
            is_running=False,
            packets_captured=classified,
            packets_classified=classified,
            message=f"Imported {processed} packet(s), classified {classified} flow(s) via hybrid SOC pipeline.",
        )

    # ------------------------------------------------------------------
    # Firewall monitor
    # ------------------------------------------------------------------

    async def start_firewall_monitor(self, req: FirewallMonitorRequest) -> FirewallMonitorResponse:
        self.registry.require_firewall_pipeline()
        set_background_event_loop(asyncio.get_running_loop())
        monitor = self._fw_monitor_state()

        if monitor["running"]:
            return FirewallMonitorResponse(
                is_running=True,
                log_path=str(monitor["log_path"]),
                lines_processed=monitor["lines_processed"],
                alerts_generated=monitor["alerts_generated"],
                message="Firewall monitor already running.",
            )

        log_path = Path(req.log_path).expanduser() if req.log_path else DEFAULT_WINDOWS_FW_LOG
        if req.log_path and req.log_path.strip().lower() == "string":
            return FirewallMonitorResponse(
                success=False,
                is_running=False,
                log_path=str(log_path),
                message=(
                    "Invalid firewall log path. Remove the placeholder \"string\" and provide "
                    "a real Windows firewall log path, or omit log_path to use the default path."
                ),
            )

        if not log_path.exists() or not log_path.is_file():
            raise ValueError(
                f"Firewall log not found: {log_path}. Enable Windows Firewall logging and verify the path."
            )

        stop_event = threading.Event()
        monitor.update({
            "running": True,
            "log_path": log_path,
            "lines_processed": 0,
            "alerts_generated": 0,
            "stop_event": stop_event,
        })

        thread = threading.Thread(
            target=_firewall_monitor_thread,
            args=(log_path, req.poll_interval_seconds, stop_event, self.registry, self.user_id),
            daemon=True,
        )
        monitor["thread"] = thread
        thread.start()

        return FirewallMonitorResponse(
            is_running=True,
            log_path=str(log_path),
            message=f"Firewall monitor started — watching {log_path}",
        )

    async def stop_firewall_monitor(self) -> FirewallMonitorResponse:
        monitor = self._fw_monitor_state()
        if not monitor["running"]:
            return FirewallMonitorResponse(
                is_running=False,
                log_path=str(monitor.get("log_path", "")),
                lines_processed=monitor["lines_processed"],
                alerts_generated=monitor["alerts_generated"],
                message="Firewall monitor is not running.",
            )

        stop_event: threading.Event = monitor.get("stop_event")
        if stop_event:
            stop_event.set()

        monitor["running"] = False
        return FirewallMonitorResponse(
            is_running=False,
            log_path=str(monitor.get("log_path", "")),
            lines_processed=monitor["lines_processed"],
            alerts_generated=monitor["alerts_generated"],
            message="Firewall monitor stopped.",
        )

    async def get_firewall_monitor_status(self) -> FirewallMonitorResponse:
        monitor = self._fw_monitor_state()
        return FirewallMonitorResponse(
            is_running=monitor["running"],
            log_path=str(monitor.get("log_path", "")),
            lines_processed=monitor["lines_processed"],
            alerts_generated=monitor["alerts_generated"],
            message="Monitor running." if monitor["running"] else "Monitor stopped.",
        )
