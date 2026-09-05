from dataclasses import dataclass
from typing import Optional

@dataclass
class PacketEvent:
    timestamp: float
    interface: str
    src_ip: str
    dst_ip: str
    proto: str
    port: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    arp_op: Optional[int] = None  # 1=request, 2=reply