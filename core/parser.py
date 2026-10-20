from scapy.layers.inet import IP, TCP, UDP


def parse_packet(packet):
    """
    Extract the useful fields needed by CapCipCup.

    Returns:
        tuple[str | None, str | None, int | None, str | None]:
        (source_ip, destination_ip, destination_port, protocol)

    protocol is "TCP", "UDP", or None.
    """

    src_ip = None
    dst_ip = None
    dest_port = None
    protocol = None

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    if packet.haslayer(TCP):
        dest_port = packet[TCP].dport
        protocol = "TCP"
    elif packet.haslayer(UDP):
        dest_port = packet[UDP].dport
        protocol = "UDP"

    return src_ip, dst_ip, dest_port, protocol
