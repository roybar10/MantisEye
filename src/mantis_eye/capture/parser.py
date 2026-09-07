import time
from scapy.all import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from mantis_eye.capture.events import PacketEvent

def build_event(pkt, interface):
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