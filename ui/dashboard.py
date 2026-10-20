from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from modules.ids import (
    DETECTION_THRESHOLD,
    get_alert_count,
    get_last_alert,
    get_packet_count,
    get_scan_tracker,
    get_udp_scan_tracker,
)


LOGO = r"""
   ██████╗ █████╗ ██████╗  ██████╗██╗██████╗  ██████╗██╗   ██╗██████╗
  ██╔════╝██╔══██╗██╔══██╗██╔════╝██║██╔══██╗██╔════╝██║   ██║██╔══██╗
  ██║     ███████║██████╔╝██║     ██║██████╔╝██║     ██║   ██║██████╔╝
  ██║     ██╔══██║██╔═══╝ ██║     ██║██╔═══╝ ██║     ██║   ██║██╔═══╝
  ╚██████╗██║  ██║██║     ╚██████╗██║██║     ╚██████╗╚██████╔╝██║
   ╚═════╝╚═╝  ╚═╝╚═╝      ╚═════╝╚═╝╚═╝      ╚═════╝ ╚═════╝ ╚═╝

             Detect and Protect Your System or Network
"""


def build_dashboard():
    stats = Table(show_header=False, expand=True)
    stats.add_row("Packets Processed", str(get_packet_count()))
    stats.add_row("Alerts Detected", str(get_alert_count()))
    stats.add_row("Status", "MONITORING")

    threats = Table(expand=True)
    threats.add_column("Source IP")
    threats.add_column("Proto")
    threats.add_column("Unique Ports", justify="right")

    for proto, tracker in (
        ("TCP", get_scan_tracker()),
        ("UDP", get_udp_scan_tracker()),
    ):
        for src_ip, ports in tracker.items():
            if len(ports) > DETECTION_THRESHOLD:
                threats.add_row(src_ip, proto, str(len(ports)))

    last_alert = get_last_alert()

    if last_alert:
        alert_panel = Panel(
            f"Type: {last_alert['type']}\n"
            f"Source: {last_alert['source_ip']}\n"
            f"Unique ports: {last_alert['unique_ports']}",
            title="Latest Alert",
        )
    else:
        alert_panel = Panel("No alerts yet.", title="Latest Alert")

    content = Group(
        LOGO,
        stats,
        Panel(threats, title="Threat Sources"),
        alert_panel,
    )

    return Panel(
        content,
        title="🛡️ CapCipCup IDS",
        subtitle="LAN web dashboard: http://<this-device-ip>:5000",
    )


def run_dashboard(stop_event):
    with Live(
        build_dashboard(),
        refresh_per_second=4,
        screen=True,
    ) as live:
        while not stop_event.is_set():
            live.update(build_dashboard())
            stop_event.wait(0.25)
