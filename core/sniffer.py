from scapy.all import sniff

from core.config import get_config


def start_sniffer(callback, interface=None):
    """
    Start packet capture and send every captured packet to callback.

    Interface defaults to sniffing.interface in config.yaml.
    """

    if interface is None:
        interface = get_config()["sniffing"]["interface"]

    sniff(
        iface=interface,
        prn=callback,
        store=False,
    )
