from core.parser import parse_packet
from core.sniffer import start_sniffer
from modules.ids import detect_port_scan, detect_udp_scan


def show_packet(packet):
    src_ip, dst_ip, dest_port, protocol = parse_packet(packet)

    if src_ip is None:
        return

    print("SNIFFING PACKET NETWORK")
    print("Source IP       :", src_ip)
    print("Destination IP  :", dst_ip)
    print("Destination Port:", dest_port)
    print("Protocol        :", protocol)
    print("-" * 50)

    if dest_port is None:
        return

    if protocol == "TCP":
        detect_port_scan(src_ip, dest_port)
    elif protocol == "UDP":
        detect_udp_scan(src_ip, dest_port)


def run():
    print("CapCipCup sniff mode")
    print("Press Ctrl+C to stop.")
    print()

    try:
        start_sniffer(show_packet)
    except KeyboardInterrupt:
        print("\nSniffing stopped.")
