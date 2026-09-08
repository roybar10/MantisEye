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
        port: Destination port for tcp/udp. None for arp.
        src_mac / dst_mac: Extracted uniformly from the Ethernet layer for every
            packet type, so any detector needing L2 identity doesn't special-case
            per-protocol parsing.
        arp_op: 1=request, 2=reply. Only set for proto="arp".
        tcp_flags: Raw flag string (e.g. "S", "RA"). Only set for proto="tcp".
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