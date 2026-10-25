# CapCipCup

**CapCipCup** is a lightweight Python intrusion detection toolkit that
sniffs packets with Scapy, detects TCP and UDP port scans, and reports
them through a terminal dashboard and a LAN web dashboard.

> Detect and Protect Your System or Network

> Stil Development

## Features

- Scapy packet capture (raw sockets, needs root)
- IP/TCP/UDP packet parsing
- TCP and UDP port-scan detection with separate per-protocol trackers
- Session-based tracking — counts reset after 5 s of idle time per source IP, so separate scans never accumulate
- Ephemeral port filter — replies to your own client ports (> 1024) never count as scans, so local router/DNS traffic does not trigger false alerts
- Severity scoring: LOW (11–20 ports), MEDIUM (21–40), HIGH (41+)
- Central configuration (`config.yaml`) with built-in defaults fallback
- Rich terminal dashboard (live, 4 refreshes per second)
- LAN web dashboard (Sortable, filterable)
- REST API: `/api/status`, `/api/alerts?since=<ISO timestamp>`
- Alert trend chart (alerts per minute) and alert history table
- Persistent event log (`logs/alerts.json`)
- 14 unit tests

## Quick start

```fish
git clone <repo-url>
cd CapCipCup
python3 -m venv venv
source venv/bin/activate.fish #if you use fish 
pip install -r requirements.txt
sudo ./venv/bin/python main.py --ids
```

## Modes

| Mode | Command | What it does |
| --- | --- | --- |
| IDS | `sudo python main.py --ids` | Full pipeline: sniffing, detection, terminal dashboard, web dashboard |
| Sniff | `sudo python main.py --sniff` | Packet capture only |

Both need root because Scapy opens raw sockets.

## Web dashboard

From any device on the same LAN:

```text
http://<ip-of-the-machine>:5000
```

The dashboard auto-refreshes every second and includes:

- Live status pill and uptime clock
- Active Threats strip with severity breakdown
- Sortable, filterable threat table (severity / protocol / IP search, keys: `/` search, `P` pause)
- Traffic chart (packets per second)
- Alerts per minute trend chart
- Alert history table
- Toast notifications for new threats
- JSON snapshot export

**Do not expose port 5000 to the public internet.** It is a local
network tool with no authentication.

## API

```text
GET /              → HTML dashboard
GET /api/status    → packets, alerts, active threats, last alert,
                     alert trend, alert history
GET /api/alerts    → full alert history
GET /api/alerts?since=2026-10-20T08:11:34 → only newer alerts
```

## Configuration

All tunables live in `config.yaml`:

```yaml
sniffing:
  interface: wlan0        # change to your interface

detection:
  detection_threshold: 10 # alert after this many unique ports
  session_timeout: 5.0    # idle seconds before a session resets
  well_known_port_max: 1024  # ignore replies to ephemeral client ports

severity:
  medium_min: 21
  high_min: 41
```

If the file is missing or corrupted, `core/config.py` falls back to
built-in defaults and monitoring continues.

## Testing

```fish
./venv/bin/python -m unittest tests.test_ids -v   # 14 tests
./venv/bin/python tests/test_session_manual.py    # real-timing scenario test
```

## Project structure

```text
CapCipCup/
├── main.py              # entry point, CLI args
├── config.yaml          # central configuration
├── requirements.txt
├── core/
│   ├── config.py        # YAML loader with defaults
│   ├── parser.py        # packet → (src, dst, dport, proto)
│   └── sniffer.py       # Scapy wrapper
├── modules/
│   ├── ids.py           # detection engine, session tracking, severity
│   ├── ids_mode.py      # IDS mode routing
│   └── sniff_mode.py    # sniff-only mode routing
├── ui/
│   └── dashboard.py     # Rich terminal dashboard
├── web/
│   ├── dashboard.py     # Flask app + API
│   └── templates/
│       └── index.html   # web dashboard frontend
└── tests/
    ├── test_ids.py      # unit tests
    └── test_session_manual.py
```

## Roadmap
> If you would like to contribute, please don't hesitate to submit a pull request.
- [x] persistent event logging (`logs/alerts.json`)
- [x] configurable thresholds (`config.yaml`)
- [x] session windows with idle timeout
- [x] TCP and UDP port-scan detection
- [x] ephemeral port filter (no router/DNS false positives)
- [x] automated tests
- [x] dashboard history, trend charts, and JSON API
- [ ] additional IDS rules (SYN flood, fragmented packet anomaly)
- [ ] firewall/IPS integration after detection is stable
