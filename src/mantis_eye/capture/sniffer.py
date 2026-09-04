import time
from typing import Optional
from scapy.all import sniff, IP, TCP, UDP
from scapy.arch import get_if_list
from mantis_eye.capture.events import PacketEvent
from mantis_eye.detection.dispatcher import Dispatcher
from mantis_eye.detection.detectors import PortScanDetector

def detect_interfaces():
    interfaces = [i for i in get_if_list() if i != "lo"]
    if not interfaces:
        raise RuntimeError("No suitable network interfaces found.")
    return interfaces

def build_event(pkt) -> Optional[PacketEvent]:
    if IP not in pkt:
        return None

    if TCP in pkt:
        proto, port = "TCP", pkt[TCP].dport
    elif UDP in pkt:
        proto, port = "UDP", pkt[UDP].dport
    else:
        proto, port = "OTHER", None

    return PacketEvent(
        timestamp=time.time(),
        interface=pkt.sniffed_on,
        src_ip=pkt[IP].src,
        dst_ip=pkt[IP].dst,
        proto=proto,
        port=port,
    )

def main():
    interfaces = detect_interfaces()
    print(f"Sniffing on interfaces: {interfaces}")

    dispatcher = Dispatcher()
    # dispatcher.register(lambda event: print(f"[EVENT] {event}"))
    dispatcher.register(PortScanDetector())
    # detectors will get registered here, next step

    def handle_packet(pkt):
        event = build_event(pkt)
        if event:
            dispatcher.dispatch(event)

    sniff(iface=interfaces, filter="tcp or udp", prn=handle_packet, count=20)

if __name__ == "__main__":
    main()