import unittest
import time

from modules.ids import (
    detect_port_scan,
    detect_udp_scan,
    get_alert_count,
    get_last_alert,
    get_packet_count,
    get_severity,
    get_scan_tracker,
    get_udp_scan_tracker,
    reset_state,
    expire_sessions,
    DETECTION_THRESHOLD,
    SESSION_TIMEOUT,
)
from core.config import get_config


class TestIDS(unittest.TestCase):

    def setUp(self):
        reset_state()

    def test_duplicate_ports_are_not_counted_twice(self):
        detect_port_scan("10.0.0.1", 80)
        detect_port_scan("10.0.0.1", 80)

        self.assertEqual(len(get_scan_tracker()["10.0.0.1"]), 1)

    def test_port_scan_alert_triggers_once(self):
        for port in range(1, 12):
            detect_port_scan("10.0.0.2", port)

        self.assertEqual(get_alert_count(), 1)
        self.assertEqual(get_packet_count(), 11)

        detect_port_scan("10.0.0.2", 12)
        self.assertEqual(get_alert_count(), 1)

    def test_different_sources_are_tracked_separately(self):
        for port in range(1, 12):
            detect_port_scan("10.0.0.3", port)

        for port in range(1, 12):
            detect_port_scan("10.0.0.4", port)

        self.assertEqual(get_alert_count(), 2)

    def test_severity_levels(self):
        """Uji batas LOW, MEDIUM, HIGH."""
        self.assertEqual(get_severity(10), "LOW")
        self.assertEqual(get_severity(11), "LOW")
        self.assertEqual(get_severity(20), "LOW")
        self.assertEqual(get_severity(21), "MEDIUM")
        self.assertEqual(get_severity(40), "MEDIUM")
        self.assertEqual(get_severity(41), "HIGH")
        self.assertEqual(get_severity(100), "HIGH")

    def test_session_timeout_resets_count(self):
        """Sesi baru tidak warisi port lama."""
        now = 1000.0

        # Scan 1: 28 port -> MEDIUM
        for port in range(1, 29):
            detect_port_scan("10.0.0.100", port, now=now)
        self.assertEqual(get_severity(28), "MEDIUM")
        self.assertEqual(get_alert_count(), 1)
        self.assertEqual(get_scan_tracker()["10.0.0.100"], set(range(1, 29)))

        # Scan 2: 100 port -> HIGH (session baru setelah timeout)
        now += 6.0  # > SESSION_TIMEOUT (5.0)
        expire_sessions(now)

        for port in range(30, 130):
            detect_port_scan("10.0.0.100", port, now=now)
        self.assertEqual(get_severity(100), "HIGH")
        self.assertEqual(len(get_scan_tracker()["10.0.0.100"]), 100)

        # Scan 3: 28 port lagi, sesi baru lagi
        now += 6.0
        expire_sessions(now)

        for port in range(200, 228):
            detect_port_scan("10.0.0.100", port, now=now)

        self.assertEqual(get_severity(28), "MEDIUM")
        self.assertEqual(get_alert_count(), 3)

        # Pastikan port lama tidak termasuk
        self.assertEqual(get_scan_tracker()["10.0.0.100"], set(range(200, 228)))

    def test_alert_not_repeated_within_same_session(self):
        """Alert hanya satu kali per sesi."""
        now = 2000.0

        # Melewati threshold
        for port in range(1, 15):
            detect_port_scan("10.0.0.200", port, now=now)

        self.assertEqual(get_alert_count(), 1)

        # Lanjut port lain dalam sesi yang sama
        for port in range(15, 30):
            detect_port_scan("10.0.0.200", port, now=now)

        self.assertEqual(get_alert_count(), 1)

    # --- Config terpusat ---

    def test_config_values_loaded(self):
        """Nilai dari config.yaml terpakai oleh detection engine."""
        config = get_config()

        self.assertEqual(DETECTION_THRESHOLD,
                         config["detection"]["detection_threshold"])
        self.assertEqual(SESSION_TIMEOUT,
                         config["detection"]["session_timeout"])
        self.assertGreater(SESSION_TIMEOUT, 0)

        # Default severity harus cocok dengan config
        self.assertEqual(get_severity(config["severity"]["medium_min"] - 1),
                         "LOW")
        self.assertEqual(get_severity(config["severity"]["medium_min"]),
                         "MEDIUM")
        self.assertEqual(get_severity(config["severity"]["high_min"]),
                         "HIGH")

    # --- UDP port scan ---

    def test_udp_scan_triggers_alert(self):
        """UDP scan melewati threshold memicu alert terpisah."""
        for port in range(1, 12):
            detect_udp_scan("10.0.0.10", port)

        self.assertEqual(get_alert_count(), 1)
        self.assertEqual(len(get_udp_scan_tracker()["10.0.0.10"]), 11)
        self.assertEqual(get_last_alert()["type"], "Possible UDP Port Scan")

    def test_tcp_and_udp_tracked_separately(self):
        """Tracker TCP dan UDP tidak saling bercampur."""
        for port in range(1, 12):
            detect_port_scan("10.0.0.11", port)

        for port in range(1, 12):
            detect_udp_scan("10.0.0.11", port)

        self.assertEqual(get_alert_count(), 2)
        self.assertEqual(len(get_scan_tracker()["10.0.0.11"]), 11)
        self.assertEqual(len(get_udp_scan_tracker()["10.0.0.11"]), 11)

    def test_udp_session_timeout_resets_count(self):
        """Sesi UDP baru tidak warisi port lama."""
        now = 3000.0

        for port in range(1, 12):
            detect_udp_scan("10.0.0.12", port, now=now)

        self.assertEqual(len(get_udp_scan_tracker()["10.0.0.12"]), 11)

        now += 6.0
        expire_sessions(now)

        for port in range(100, 111):
            detect_udp_scan("10.0.0.12", port, now=now)

        self.assertEqual(get_udp_scan_tracker()["10.0.0.12"],
                         set(range(100, 111)))

    # --- Filter port ephemeral (bug router lokal) ---

    def test_client_responses_do_not_trigger_alert(self):
        """Respons ke port ephemeral bukan port scan."""
        # Router sebagai DNS lokal membalas ke port random tiap query.
        for port in range(40000, 40050):
            detect_udp_scan("192.168.1.1", port)

        self.assertEqual(get_alert_count(), 0)
        self.assertNotIn("192.168.1.1", get_udp_scan_tracker())

    def test_tcp_client_responses_do_not_trigger_alert(self):
        """SYN-ACK dari gateway ke port ephemeral juga bukan scan."""
        for port in range(50000, 50050):
            detect_port_scan("192.168.1.1", port)

        self.assertEqual(get_alert_count(), 0)
        self.assertNotIn("192.168.1.1", get_scan_tracker())

    def test_ephemeral_packets_still_counted(self):
        """Paket ephemeral tetap dihitung sebagai paket, bukan port."""
        detect_udp_scan("192.168.1.1", 40000)

        self.assertEqual(get_packet_count(), 1)
        self.assertNotIn("192.168.1.1", get_udp_scan_tracker())

    def test_well_known_scan_still_detected(self):
        """Scan port well-known tetap terdeteksi setelah filter."""
        for port in range(1, 12):
            detect_udp_scan("192.168.1.99", port)

        self.assertEqual(get_alert_count(), 1)
        self.assertEqual(len(get_udp_scan_tracker()["192.168.1.99"]), 11)


if __name__ == "__main__":
    unittest.main()
