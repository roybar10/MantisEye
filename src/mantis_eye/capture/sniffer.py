from functools import partial
from scapy.all import sniff
from mantis_eye.capture.interfaces import detect_interfaces
from mantis_eye.capture.parser import build_event
from mantis_eye.detection.dispatcher import Dispatcher

def handle_packet(pkt, dispatcher):
    event = build_event(pkt, pkt.sniffed_on)
    if event:
        dispatcher.dispatch(event)

def main():
    interfaces = detect_interfaces()
    print(f"Sniffing on interfaces: {interfaces}")

    dispatcher = Dispatcher()

    sniff(
        iface=interfaces,
        filter="tcp or udp",
        prn=partial(handle_packet, dispatcher=dispatcher),
        count=0,
    )

if __name__ == "__main__":
    main()