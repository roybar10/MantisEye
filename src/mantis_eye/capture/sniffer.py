"""Entry point: wires interface detection, parsing, and dispatch into a live capture loop.

Deliberately owns no detection logic — it only builds a Dispatcher and hands it
each PacketEvent. Adding, removing, or reconfiguring detectors never requires
touching this file. On Ctrl+C it prints the attacker summary the Dispatcher
builds from the detectors' own data."""

from functools import partial
from scapy.all import sniff

from mantis_eye.netinfo.interfaces import detect_interfaces
from mantis_eye.capture.parser import build_event
from mantis_eye.detection.dispatcher import Dispatcher 
from mantis_eye.detection.attacks import Attacker

def handle_packet(pkt, dispatcher):
    """Per-packet callback: parse then dispatch.

    Kept as a top-level function (not a closure) so it's directly unit-testable
    with a fake dispatcher, independent of the live sniff() loop.

    Args:
        pkt: Raw Scapy packet.
        dispatcher: Dispatcher instance to route the resulting event to.
    """

    event = build_event(pkt, pkt.sniffed_on)
    if event:
        dispatcher.dispatch(event)

def main():
    """Detect interfaces, build the dispatcher, sniff until Ctrl+C, then print
    the attacker summary.

    Synchronous per-packet pipeline is deliberate — packets are parsed and
    dispatched inline, no queue/worker decoupling. Revisit only if load testing
    shows sniff() falling behind. Ctrl+C is caught here because some Scapy
    versions swallow it and return from sniff() normally; this way the summary
    prints either way.
    """
    
    interfaces = detect_interfaces()
    print(f"Sniffing on interfaces: {interfaces}")

    dispatcher = Dispatcher()

    try:
        sniff(
        iface=interfaces,
        filter=dispatcher.bpf_filter(),
        prn=partial(handle_packet, dispatcher=dispatcher),
        count=0,)

    except KeyboardInterrupt:
        pass

    print(Attacker.summarize(dispatcher.attackers()))

if __name__ == "__main__":
    main()