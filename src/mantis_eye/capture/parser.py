"""Translates raw Scapy packets into PacketEvent.

This is the ONLY place that touches the Scapy API. When migrating to dpkt,
this function is rewritten and nothing else in the codebase changes — that's
the entire point of the PacketEvent anti-corruption layer."""

import time
from scapy.all import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from mantis_eye.core.packet_event import PacketEvent

def build_event(pkt, interface):
    """Parse one Scapy packet into a PacketEvent, or None if not relevant.

    Handles ARP, TCP, and UDP. MAC addresses are pulled from the Ethernet layer
    once, up front, since every branch needs them — avoids duplicating that
    extraction per protocol. Protocol-specific fields (port, arp_op, tcp_flags)
    are set only in their relevant branch; PacketEvent is constructed exactly
    once at the end with shared defaults plus whatever the branch filled in.

    Args:
        pkt: Raw Scapy packet from the sniff() callback.
        interface: Interface the packet was captured on (Scapy's pkt.sniffed_on).

    Returns:
        PacketEvent, or None if the packet is neither ARP nor IP/TCP/UDP.
    """
    
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else None
    port = None
    arp_op = None
    tcp_flags = None

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        proto = "arp"
        src_ip = arp.psrc
        dst_ip = arp.pdst
        arp_op = arp.op

    elif pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if pkt.haslayer(TCP):
            proto = "tcp"
            port = pkt[TCP].dport
            tcp_flags = str(pkt[TCP].flags)

        elif pkt.haslayer(UDP):
            proto = "udp"
            port = pkt[UDP].dport

        else:
            return None

    else:
        return None

    return PacketEvent(
        timestamp=time.time(),
        interface=interface,
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=proto,
        port=port,
        src_mac=src_mac,
        dst_mac=dst_mac,
        arp_op=arp_op,
        tcp_flags=tcp_flags,
    )