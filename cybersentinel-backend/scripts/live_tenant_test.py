"""Live tenant isolation check against running CyberSentinel API."""

from __future__ import annotations

import sys
import time

import httpx

BASE = "http://127.0.0.1:8000"
ADMIN_EMAIL = "admin@cybersentinel.local"
ADMIN_PASSWORD = "admin123"
NEW_EMAIL = f"tenant.live.{int(time.time())}@example.com"
NEW_PASSWORD = "testpass12345"

SAMPLE_FLOW = {
    "Flow Duration": 1_200_000,
    "Total Fwd Packets": 6,
    "Total Backward Packets": 5,
    "Total Length of Fwd Packets": 400,
    "Total Length of Bwd Packets": 900,
    "Fwd Packet Length Max": 80,
    "Fwd Packet Length Min": 20,
    "Fwd Packet Length Mean": 50.0,
    "Fwd Packet Length Std": 15.0,
    "Bwd Packet Length Max": 200,
    "Bwd Packet Length Min": 40,
    "Bwd Packet Length Mean": 120.0,
    "Bwd Packet Length Std": 40.0,
    "src_ip": "10.0.0.1",
    "dst_ip": "8.8.8.8",
    "dst_port": 443,
    "protocol": "TCP",
}


def login(email: str, password: str) -> tuple[str, str, str]:
    response = httpx.post(
        f"{BASE}/api/v1/auth/token",
        data={"username": email, "password": password},
        timeout=30.0,
    )
    response.raise_for_status()
    payload = response.json()
    return payload["access_token"], payload.get("email", email), payload.get("role", "")


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def dashboard(token: str) -> dict:
    response = httpx.get(
        f"{BASE}/api/v1/dashboard/summary",
        headers=auth_headers(token),
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json()


def packet_events(token: str) -> dict:
    response = httpx.get(
        f"{BASE}/api/v1/packet/events",
        headers=auth_headers(token),
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json()


def classify(token: str) -> int:
    response = httpx.post(
        f"{BASE}/api/v1/packet/classify",
        headers=auth_headers(token),
        json={"flow": SAMPLE_FLOW},
        timeout=60.0,
    )
    return response.status_code


def main() -> int:
    print("=== LIVE TENANT ISOLATION TEST ===\n")

    admin_token, admin_email, admin_role = login(ADMIN_EMAIL, ADMIN_PASSWORD)
    print(f"[1] Admin login OK: {admin_email} ({admin_role})")

    admin_before = dashboard(admin_token)
    admin_events_before = packet_events(admin_token)
    print(
        f"    Admin dashboard before: packets={admin_before.get('packet_events')}, "
        f"alerts={admin_before.get('firewall_alerts')}"
    )
    print(f"    Admin packet events before: total={admin_events_before.get('total')}")

    status = classify(admin_token)
    if status != 200:
        print(f"    FAIL admin classify HTTP {status}")
        return 1
    print("    Admin created one packet classification")

    admin_after = dashboard(admin_token)
    admin_events_after = packet_events(admin_token)
    admin_packet_total = int(admin_events_after.get("total", 0))
    print(
        f"    Admin after classify: packets={admin_after.get('packet_events')}, "
        f"events total={admin_packet_total}\n"
    )

    register = httpx.post(
        f"{BASE}/api/v1/auth/register",
        json={"email": NEW_EMAIL, "password": NEW_PASSWORD},
        timeout=30.0,
    )
    print(f"[2] Register new user: {NEW_EMAIL} -> HTTP {register.status_code}")
    if register.status_code != 201:
        print(register.text)
        return 1
    print(f"    User id: {register.json().get('id')}\n")

    new_token, new_email, new_role = login(NEW_EMAIL, NEW_PASSWORD)
    print(f"[3] New user login OK: {new_email} ({new_role})")

    new_dash = dashboard(new_token)
    new_events = packet_events(new_token)
    print(
        f"    Dashboard: packets={new_dash.get('packet_events')}, "
        f"alerts={new_dash.get('firewall_alerts')}, "
        f"actions={new_dash.get('response_actions')}"
    )
    print(f"    Packet events total: {new_events.get('total')}")
    print(f"    Trend points: {len(new_dash.get('trend', []))}")

    new_empty = (
        new_dash.get("packet_events") == 0
        and new_dash.get("firewall_alerts") == 0
        and new_dash.get("response_actions") == 0
        and new_events.get("total") == 0
    )
    print(f"    NEW USER EMPTY: {'PASS' if new_empty else 'FAIL'}\n")

    own_status = classify(new_token)
    new_events_after = packet_events(new_token)
    print(f"[4] New user classified own packet: HTTP {own_status}")
    print(f"    New user events after own classify: {new_events_after.get('total')}")
    new_only_own = new_events_after.get("total") == 1
    print(f"    NEW USER ONLY OWN DATA: {'PASS' if new_only_own else 'FAIL'}\n")

    admin_token2, _, _ = login(ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_final = dashboard(admin_token2)
    admin_events_final = packet_events(admin_token2)
    admin_kept = int(admin_events_final.get("total", 0)) >= admin_packet_total
    print("[5] Admin re-login")
    print(
        f"    Admin packets={admin_final.get('packet_events')}, "
        f"events total={admin_events_final.get('total')}"
    )
    print(f"    ADMIN DATA PRESERVED: {'PASS' if admin_kept else 'FAIL'}\n")

    all_pass = new_empty and new_only_own and admin_kept
    print("=== RESULT:", "ALL PASSED" if all_pass else "SOME CHECKS FAILED", "===")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
