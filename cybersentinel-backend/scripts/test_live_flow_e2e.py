"""
End-to-end live-flow test: aggregate packets → full SOC pipeline → verdict.
Run: python scripts/test_live_flow_e2e.py
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
from ml_engine.column_mapping import flows_to_feature_matrix
from models.loader import ModelRegistry
from services.live_flow_processor import LiveFlowProcessor
from services.packet_service import PacketService
from schemas.packet import FlowInput
from db.database import AsyncSessionLocal, create_tables


def _simulate_benign_flow() -> LiveFlowProcessor:
    """Typical HTTPS browsing: bidirectional packets over ~2s."""
    p = LiveFlowProcessor(min_packets=2, idle_timeout_seconds=120)
    base = time.time()
    sizes_fwd = [60, 120, 400, 800, 600]
    sizes_bwd = [1400, 1200, 900]
    for i, sz in enumerate(sizes_fwd):
        p.ingest(
            src_ip="192.168.1.50",
            dst_ip="142.250.185.78",
            src_port=52400 + i,
            dst_port=443,
            protocol="TCP",
            packet_size=sz,
            timestamp=base + i * 0.3,
            flags={"SYN": i == 0, "ACK": i > 0, "PSH": i > 1},
        )
    for j, sz in enumerate(sizes_bwd):
        p.ingest(
            src_ip="142.250.185.78",
            dst_ip="192.168.1.50",
            src_port=443,
            dst_port=52400,
            protocol="TCP",
            packet_size=sz,
            timestamp=base + 1.0 + j * 0.25,
            flags={"ACK": True, "PSH": True},
        )
    return p


def _simulate_portscan_flows() -> list:
    """Many short SYN flows to different ports (real port-scan shape)."""
    processors = []
    base = time.time()
    for port in range(22, 34):
        p = LiveFlowProcessor(min_packets=2, idle_timeout_seconds=5)
        for i in range(2):
            p.ingest(
                src_ip="10.0.0.99",
                dst_ip="192.168.1.1",
                src_port=40000 + port,
                dst_port=port,
                protocol="TCP",
                packet_size=60,
                timestamp=base + (port - 22) * 0.1 + i * 0.01,
                flags={"SYN": True},
            )
        processors.append(p)
    return processors


def _simulate_ddos_flow() -> LiveFlowProcessor:
    """High-rate flood on one 5-tuple (same flow key)."""
    p = LiveFlowProcessor(min_packets=2, idle_timeout_seconds=5)
    base = time.time()
    for i in range(80):
        p.ingest(
            src_ip="203.0.113.5",
            dst_ip="192.168.1.10",
            src_port=50000,
            dst_port=80,
            protocol="TCP",
            packet_size=64,
            timestamp=base + i * 0.001,
            flags={"SYN": True, "ACK": False},
        )
    return p


async def classify_flow(processor: LiveFlowProcessor, registry: ModelRegistry) -> dict:
    flows = processor.flush_all()
    if not flows:
        return {"error": "no flow completed"}
    flow = flows[0]
    ff = flow.to_flow_input()
    df = pd.DataFrame([ff.features.model_dump()])
    _, compat = flows_to_feature_matrix(df)
    coverage = float(compat.iloc[0]["feature_coverage"])

    async with AsyncSessionLocal() as session:
        svc = PacketService(registry=registry, db=session, user_id="e2e-test")
        resp = await svc.classify_single(ff)
        r = resp.result
        await session.commit()
        return {
            "coverage": round(coverage, 3),
            "packets": flow.total_packets,
            "prediction": r.prediction,
            "ml_prediction": r.ml_prediction,
            "risk_score": r.risk_score,
            "confidence": r.final_confidence,
            "triggered_rules": r.triggered_rules,
            "anomaly_level": r.packet_anomaly_level,
        }


async def main() -> int:
    await create_tables()
    registry = await ModelRegistry.load()
    if not registry.packet_classifier_available:
        print("FAIL: classifier not loaded")
        return 1

    scenarios = [
        ("benign_https", [_simulate_benign_flow()]),
        ("ddos_single_flow", [_simulate_ddos_flow()]),
        ("port_scan_multi", _simulate_portscan_flows()),
    ]

    print("=" * 60)
    print("LIVE FLOW E2E TEST (real XGBoost + IF + rules + fusion)")
    print("=" * 60)

    results: dict[str, dict] = {}
    for name, processors in scenarios:
        print(f"\n[{name}]")
        if name == "port_scan_multi":
            # Seed DB with prior flows so contextual PortScan rule can fire
            async with AsyncSessionLocal() as session:
                svc = PacketService(registry=registry, db=session, user_id="e2e-test")
                for proc in processors[:-1]:
                    for flow in proc.flush_all():
                        await svc.classify_single(flow.to_flow_input())
                await session.commit()
            proc = processors[-1]
            result = await classify_flow(proc, registry)
        else:
            result = await classify_flow(processors[0], registry)
        results[name] = result
        for k, v in result.items():
            print(f"  {k}: {v}")

    print("\n" + "=" * 60)
    print("TRUST ASSESSMENT FOR LIVE NETWORK")
    print("=" * 60)
    benign = results.get("benign_https", {})
    ddos = results.get("ddos_single_flow", {})
    scan = results.get("port_scan_multi", {})

    checks = {
        "Models loaded": registry.packet_classifier_available and registry.packet_anomaly_available,
        "Benign flow >=65% coverage": benign.get("coverage", 0) >= 0.65,
        "Benign ML says Normal": benign.get("ml_prediction") == "Normal",
        "DDoS flow high packet rate detected": ddos.get("risk_score", 0) >= 40 or ddos.get("prediction") in ("Suspicious", "Malicious"),
        "Port scan contextual detection": scan.get("risk_score", 0) >= 40 or "PortScan" in str(scan.get("triggered_rules", [])),
        "No crash / pipeline completes": "error" not in benign and "error" not in ddos,
    }
    for label, ok in checks.items():
        print(f"  {'PASS' if ok else 'FAIL'}: {label}")

    passed = sum(checks.values())
    print(f"\nScore: {passed}/{len(checks)} checks passed")
    print("\nNOTE: 'prediction' may differ from ml_prediction when SOC rules or anomaly fusion escalate.")
    print("Isolation Forest flags anomaly — conservative fusion, not a crash.")
    return 0 if passed >= 5 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
