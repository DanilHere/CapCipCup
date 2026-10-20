"""
CapCipCup IDS detection engine.

Detection rules:
- TCP port scan: a source IP is suspicious after it contacts more
  than DETECTION_THRESHOLD unique destination ports.
- UDP port scan: same rule with a separate per-protocol tracker.

Port counts are tracked per session. A session ends after
SESSION_TIMEOUT seconds of inactivity from a source IP, so counts
never accumulate across separate scans.
"""

from collections import deque
import time

import json
from datetime import datetime, timedelta
from pathlib import Path

from core.config import get_config

performance_history = deque(maxlen=60)
last_sample_time = time.time()
last_sample_packets = 0

# --- Configuration (centralised in config.yaml) ---
_config = get_config()
DETECTION_THRESHOLD = int(_config["detection"]["detection_threshold"])
SESSION_TIMEOUT = float(_config["detection"]["session_timeout"])
WELL_KNOWN_PORT_MAX = int(_config["detection"]["well_known_port_max"])
MEDIUM_MIN = int(_config["severity"]["medium_min"])
HIGH_MIN = int(_config["severity"]["high_min"])

# --- Session tracking ---
# Unique ports are counted per scan session, never cumulatively forever.
# A session ends after SESSION_TIMEOUT of inactivity from the source IP.
TCP_ALERT = "Possible TCP Port Scan"
UDP_ALERT = "Possible UDP Port Scan"

scan_tracker = {}
session_last_seen = {}
alerted_sources = set()
alerted_severity = {}

udp_scan_tracker = {}
udp_session_last_seen = {}
udp_alerted_sources = set()
udp_alerted_severity = {}

alert_count = 0
packet_count = 0
last_alert = None

# History of every alert ever raised (bounded, newest last).
# Used by the dashboards to show trend charts and alert history.
alert_history = deque(maxlen=500)


"""
Save log alert to JSON format
"""
def _log_paths():
    root = Path(__file__).resolve().parent.parent
    log_dir = root / "logs"
    return log_dir, log_dir / "alerts.json"


def save_alert(alert):
    log_dir, log_file = _log_paths()
    try:
        log_dir.mkdir(parents=True, exist_ok=True)

        alerts = []
        if log_file.exists():
            try:
                content = log_file.read_text().strip()
                if content:
                    alerts = json.loads(content)
                    if not isinstance(alerts, list):
                        alerts = []
            except (json.JSONDecodeError, OSError):
                alerts = []

        alerts.append({
            "timestamp": datetime.now().isoformat(),
            **alert
        })

        log_file.write_text(json.dumps(alerts, indent=4))
    except OSError as exc:
        # Logging must never stop packet monitoring.
        print(f"[WARN] failed to save alert: {exc}")

"""
Severity Scoring
"""
def get_severity(port_count):
    if port_count >= HIGH_MIN:
        return "HIGH"
    elif port_count >= MEDIUM_MIN:
        return "MEDIUM"
    else:
        return "LOW"


def _maybe_expire(tracker, last_seen, alerted, alerted_sev, src_ip, now):
    """Reset the scan session if idle past SESSION_TIMEOUT."""
    last = last_seen.get(src_ip)
    if last is None:
        return False
    if now - last >= SESSION_TIMEOUT:
        tracker[src_ip] = set()
        alerted.discard(src_ip)
        alerted_sev.pop(src_ip, None)
        return True
    return False


def _detect_scan(tracker, last_seen, alerted, alerted_sev,
                 src_ip, dest_port, now, alert_type):
    """
    Generic scan detector for a single protocol.

    Duplicate ports do not increase the count because ports are stored
    in a set. A new session starts when the source IP has been idle
    for SESSION_TIMEOUT seconds.

    Ports above WELL_KNOWN_PORT_MAX are ignored: those are our own
    ephemeral client ports, e.g. local DNS responses from the router.
    """

    global alert_count, packet_count, last_alert

    if now is None:
        now = time.monotonic()

    packet_count += 1

    # Replies to our own ephemeral client ports are not port scans.
    if dest_port > WELL_KNOWN_PORT_MAX:
        return

    if src_ip not in tracker:
        tracker[src_ip] = set()
    else:
        _maybe_expire(tracker, last_seen, alerted, alerted_sev, src_ip, now)

    last_seen[src_ip] = now
    tracker[src_ip].add(dest_port)

    port_count = len(tracker[src_ip])

    severity = get_severity(port_count)

    if port_count > DETECTION_THRESHOLD:
        if src_ip not in alerted:
            alerted.add(src_ip)
            alerted_sev[src_ip] = severity
            alert_count += 1

            last_alert = {
                "source_ip": src_ip,
                "unique_ports": port_count,
                "type": alert_type,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
            }

            alert_history.append(dict(last_alert))

            save_alert(last_alert)
            print(f"[ALERT] {alert_type} from {src_ip} [{severity}]")
        else:
            # Existing session: refresh last_alert so the dashboard stays
            # consistent, without raising a new alert (1 alert per session).
            alerted_sev[src_ip] = severity
            if (
                last_alert
                and last_alert.get("source_ip") == src_ip
                and last_alert.get("type") == alert_type
            ):
                last_alert["unique_ports"] = port_count
                last_alert["severity"] = severity


def detect_port_scan(src_ip, dest_port, now=None):
    """Process one TCP source IP / destination port pair."""
    _detect_scan(
        scan_tracker, session_last_seen,
        alerted_sources, alerted_severity,
        src_ip, dest_port, now, TCP_ALERT,
    )


def detect_udp_scan(src_ip, dest_port, now=None):
    """Process one UDP source IP / destination port pair."""
    _detect_scan(
        udp_scan_tracker, udp_session_last_seen,
        udp_alerted_sources, udp_alerted_severity,
        src_ip, dest_port, now, UDP_ALERT,
    )


def get_alert_count():
    return alert_count


def get_packet_count():
    return packet_count


def get_scan_tracker():
    return scan_tracker


def get_udp_scan_tracker():
    return udp_scan_tracker


def get_last_alert():
    return last_alert


def get_alert_history():
    """Return a copy of the alert history (newest last)."""
    return list(alert_history)


def get_alert_trend(minutes=60):
    """
    Return alerts-per-minute for the last `minutes` minutes.

    Output: [{"minute": "2026-10-15T10:05", "count": 3}, ...]
    Buckets are aligned to the minute; empty minutes are included.
    """
    now = datetime.now()
    start = now - timedelta(minutes=minutes - 1)

    buckets = {}
    for entry in alert_history:
        ts = entry.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts)
        except ValueError:
            continue
        if dt < start:
            continue
        key = dt.strftime("%Y-%m-%dT%H:%M")
        buckets[key] = buckets.get(key, 0) + 1

    result = []
    cursor = start.replace(second=0, microsecond=0)
    while cursor <= now.replace(second=0, microsecond=0):
        key = cursor.strftime("%Y-%m-%dT%H:%M")
        result.append({"minute": key, "count": buckets.get(key, 0)})
        cursor += timedelta(minutes=1)

    return result


def get_alerts_since(iso_timestamp):
    """Return alerts newer than the given ISO timestamp (string)."""
    try:
        cutoff = datetime.fromisoformat(iso_timestamp)
    except ValueError:
        return []

    return [e for e in alert_history
            if e.get("timestamp") and
            _parse_iso(e["timestamp"]) >= cutoff]


def _parse_iso(value):
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def reset_state():
    """
    Reset IDS runtime state.

    Useful for tests or restarting the detector without restarting
    the whole Python process.
    """

    global alert_count, packet_count, last_alert

    scan_tracker.clear()
    session_last_seen.clear()
    alerted_sources.clear()
    alerted_severity.clear()

    udp_scan_tracker.clear()
    udp_session_last_seen.clear()
    udp_alerted_sources.clear()
    udp_alerted_severity.clear()

    alert_history.clear()

    alert_count = 0
    packet_count = 0
    last_alert = None


def expire_sessions(now=None):
    """Expire all idle sessions (for testing)."""
    if now is None:
        now = time.monotonic()
    for tracker, last_seen, alerted, alerted_sev in (
        (scan_tracker, session_last_seen, alerted_sources, alerted_severity),
        (udp_scan_tracker, udp_session_last_seen,
         udp_alerted_sources, udp_alerted_severity),
    ):
        for src_ip in list(tracker.keys()):
            _maybe_expire(tracker, last_seen, alerted, alerted_sev, src_ip, now)
