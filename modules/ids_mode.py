from threading import Event, Thread

from core.parser import parse_packet
from core.sniffer import start_sniffer
from modules.ids import detect_port_scan, detect_udp_scan
from ui.dashboard import run_dashboard
from web.dashboard import run_web_dashboard


def analyze_packet(packet):
    """
    Parse a captured packet and pass useful information to the IDS.
    """

    src_ip, _dst_ip, dest_port, protocol = parse_packet(packet)

    if src_ip is None or dest_port is None:
        return

    if protocol == "TCP":
        detect_port_scan(src_ip, dest_port)
    elif protocol == "UDP":
        detect_udp_scan(src_ip, dest_port)


def run():
    """
    Run packet capture, terminal dashboard, and LAN web dashboard
    inside the same process so they share IDS state.
    """

    stop_event = Event()

    dashboard_thread = Thread(
        target=run_dashboard,
        args=(stop_event,),
        daemon=True,
    )

    web_thread = Thread(
        target=run_web_dashboard,
        args=(stop_event,),
        daemon=True,
    )

    dashboard_thread.start()
    web_thread.start()

    try:
        start_sniffer(analyze_packet)
    except KeyboardInterrupt:
        print("\nStopping CapCipCup...")
    finally:
        stop_event.set()
