"""Data contract for a parsed packet.

PacketEvent is the anti-corruption layer between the capture library (Scapy today,
dpkt later) and all detection logic. Detectors only ever depend on this shape.
When migrating capture libraries, only build_event() needs to change — nothing
downstream does.
"""

from dataclasses import dataclass
from typing import Optional

@dataclass
class PacketEvent:
    
"""A single normalized packet observation.

    Attributes:
        timestamp: Capture time (epoch seconds).
        interface: Interface the packet was observed on. Detectors that are
            topology-sensitive (e.g. ARP spoofing) key state per-interface;
            detectors that aren't (e.g. cross-interface exfiltration) can
            ignore this field.
        src_ip / dst_ip: Source/destination IP (or ARP psrc/pdst for ARP packets).
        proto: One of "tcp", "udp", "arp". Drives Dispatcher routing.
        port: The port a packet is "about" for scan detection. For udp it is
            the destination port. For tcp it is the destination port of a
            SYN but the source port of a reply (RST, RST-ACK, SYN-ACK), so a
            reply carries the same port as the SYN it answers. None for arp.
        src_mac / dst_mac: Extracted uniformly from the Ethernet layer for every
            packet type, so any detector needing L2 identity doesn't special-case
            per-protocol parsing.
        arp_op: 1=request, 2=reply. Only set for proto="arp".
        tcp_flags: Raw flag string (e.g. "S", "RA", "SA"). Only set for proto="tcp".
        src_port / dst_port: The tcp source and destination ports exactly as
            on the wire, unlike port, which is direction-adjusted. Together
            with the IPs they identify one connection. Only set for proto="tcp".
        seq / ack: The tcp sequence and acknowledgment numbers. A reply to a
            SYN carries ack == SYN's seq + 1, which lets a detector match a
            reply to its SYN exactly. Only set for proto="tcp".
    """

    timestamp: float
    interface: str
    src_ip: str
    dst_ip: str
    proto: str
    port: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    arp_op: Optional[int] = None  # 1=request, 2=reply
    tcp_flags: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    seq: Optional[int] = None
    ack: Optional[int] = None