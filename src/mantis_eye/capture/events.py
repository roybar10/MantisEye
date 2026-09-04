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