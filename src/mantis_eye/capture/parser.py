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

    Handles ARP, TCP, and UDP. MAC addresses are pulled from the Ethernet
    layer once, up front, since every branch needs them, which avoids
    duplicating that extraction per protocol. Protocol-specific fields are
    set only in their relevant branch; PacketEvent is constructed exactly
    once at the end with shared defaults plus whatever the branch filled in.

    For ARP, that is arp_op. For TCP, tcp_flags, src_port, dst_port, seq and
    ack are always filled, and port is the port being probed: the
    destination port for a SYN, but the source port for a reply (RST,
    RST-ACK or SYN-ACK), so a reply and the SYN it answers carry the same
    port. The detector pairs them by the full connection tuple and the
    seq/ack numbers, not by port alone. For UDP, port is the destination
    port.

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
    src_port = None
    dst_port = None
    seq = None
    ack = None

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
            tcp_flags = str(pkt[TCP].flags)
            port = pkt[TCP].sport if tcp_flags in ("R", "RA", "SA") else pkt[TCP].dport
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            seq = pkt[TCP].seq
            ack = pkt[TCP].ack

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
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
    )