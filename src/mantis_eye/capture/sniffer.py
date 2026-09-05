import time
import subprocess
from typing import Optional
from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.arch import get_if_list
from mantis_eye.capture.events import PacketEvent
from mantis_eye.detection.dispatcher import Dispatcher
from mantis_eye.detection.detectors import PortScanDetector

def get_bridge_members():
    """Return a set of interfaces that are members of any bridge."""
    members = set()
    try:
        output = subprocess.check_output(["ip", "-o", "link", "show"], text=True)
        for line in output.splitlines():
            if "master" in line:
                iface = line.split(":")[1].strip().split("@")[0]
                members.add(iface)
    except subprocess.CalledProcessError:
        pass
    return members

def detect_interfaces():
    interfaces = [i for i in get_if_list() if i != "lo"]
    if not interfaces:
        raise RuntimeError("No suitable network interfaces found.")
    bridge_members = get_bridge_members()
    return [i for i in interfaces if i not in bridge_members]

def build_event(pkt, interface):
    
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else None
    port = None
    arp_op = None

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
        arp_op=arp_op,)

def main():
    interfaces = detect_interfaces()
    print(f"Sniffing on interfaces: {interfaces}")

    dispatcher = Dispatcher()
    # dispatcher.register(lambda event: print(f"[EVENT] {event}"))
    dispatcher.register(PortScanDetector())
    # detectors will get registered here, next step

    def handle_packet(pkt):
        event = build_event(pkt, pkt.sniffed_on)
        if event:
            dispatcher.dispatch(event)

    sniff(iface=interfaces, filter="tcp or udp", prn=handle_packet, count=0)

if __name__ == "__main__":
    main()