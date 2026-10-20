#!/usr/bin/env python3
"""
Manual test untuk session timeout dengan real timing.
Simulasi 3 skenario dari PRD: 28 port MEDIUM, 100 port HIGH, 28 port MEDIUM.
"""

import time
from modules.ids import (
    detect_port_scan,
    get_severity,
    get_scan_tracker,
    get_alert_count,
    get_last_alert,
    reset_state,
)

def print_status(label, src_ip="10.0.0.1"):
    tracker = get_scan_tracker()
    ports = len(tracker.get(src_ip, set()))
    severity = get_severity(ports) if ports > 0 else "NONE"
    alert = get_last_alert()
    print(f"\n[{label}]")
    print(f"  Ports: {ports}, Severity: {severity}")
    print(f"  Alerts: {get_alert_count()}")
    if alert:
        print(f"  Last alert: {alert['source_ip']} {alert['unique_ports']} port [{alert['severity']}]")

def main():
    reset_state()
    src_ip = "10.0.0.1"

    print("=== Test Skenario 3 Severity ===\n")

    # Skenario 1: 28 port -> MEDIUM
    print("1. Scan 28 port unik...")
    now = time.monotonic()
    for port in range(1, 29):
        detect_port_scan(src_ip, port, now=now)
    print_status("Setelah scan 28 port", src_ip)
    assert get_severity(28) == "MEDIUM", f"Expected MEDIUM, got {get_severity(28)}"
    assert get_alert_count() == 1, f"Expected 1 alert, got {get_alert_count()}"

    # Skenario 2: Tunggu 6 detik, scan 100 port -> HIGH
    print("\n2. Tunggu 6 detik (timeout 5s), scan 100 port baru...")
    time.sleep(6)
    now = time.monotonic()
    for port in range(100, 200):
        detect_port_scan(src_ip, port, now=now)
    print_status("Setelah scan 100 port (sesi baru)", src_ip)
    assert get_severity(100) == "HIGH", f"Expected HIGH, got {get_severity(100)}"
    assert get_alert_count() == 2, f"Expected 2 alerts, got {get_alert_count()}"

    # Skenario 3: Tunggu 6 detik lagi, scan 28 port -> MEDIUM (bukan HIGH)
    print("\n3. Tunggu 6 detik lagi, scan 28 port baru...")
    time.sleep(6)
    now = time.monotonic()
    for port in range(300, 328):
        detect_port_scan(src_ip, port, now=now)
    print_status("Setelah scan 28 port (sesi ketiga)", src_ip)
    assert get_severity(28) == "MEDIUM", f"Expected MEDIUM, got {get_severity(28)}"
    assert get_alert_count() == 3, f"Expected 3 alerts, got {get_alert_count()}"

    # Verifikasi port lama tidak terakumulasi
    tracker = get_scan_tracker()
    ports_in_session = tracker[src_ip]
    assert ports_in_session == set(range(300, 328)), f"Port lama terakumulasi! Got {ports_in_session}"

    print("\n✓ Semua skenario PASS")

if __name__ == "__main__":
    main()
