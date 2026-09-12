# detection/detectors/arp_spoof.py
"""Detects ARP spoofing by watching for IP->MAC binding changes on ARP replies.

Bindings are scoped per-interface and never expire — unlike port scan
state, an IP's MAC shouldn't go "stale" just from inactivity, and expiring
it would just reopen the door to the same spoof. Note this only catches
spoofs visible to the router's sniffer: on a bridge without port
mirroring, purely host-to-host ARP replies may never reach it.
"""

from mantis_eye.core.packet_event import PacketEvent

class ArpSpoofDetector:
    """Alerts when an IP with a known MAC suddenly claims a different one."""

    def __init__(self):
        """Empty (interface, ip) -> mac binding table. Per-interface keying
        keeps the same IP on two interfaces tracked independently, which
        matters if this ever runs on a router with real VLAN separation.
        """
        self.bindings: dict[tuple[str, str], str] = {}

    def __call__(self, event: PacketEvent):
        """Learns or checks an IP's MAC from a single ARP event.

        Only ARP replies (op=2) are trusted to establish a binding — requests
        are broadcast queries and don't assert "I am this IP" the way a reply
        does, so keying off them would add noise from legitimate gratuitous
        ARP. The first reply seen for an IP sets the trusted MAC; any later
        reply with a different MAC triggers an alert.
        """
        if event.arp_op != 2:
            return

        key = (event.interface, event.src_ip)
        known_mac = self.bindings.get(key)

        if known_mac is None:
            self.bindings[key] = event.src_mac
            return

        if known_mac != event.src_mac:
            self._alert(event, known_mac)
            self.bindings[key] = event.src_mac  # trust the latest claim, alert once per change

    def _alert(self, event: PacketEvent, known_mac: str):
        """Prints an ARP spoof alert showing the IP's old MAC vs. the newly
        claimed one, plus which MAC the spoofed reply was addressed to.
        """
        print(
            f"[ALERT] ARP spoof suspected on {event.interface}: "
            f"{event.src_ip} was {known_mac}, now claimed by {event.src_mac} "
            f"(targeting {event.dst_mac})"
        )