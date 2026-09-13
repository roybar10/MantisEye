"""Detects ARP spoofing on the LAN by watching for IP->MAC binding changes.

Scoped to LAN-facing interfaces only, since ARP spoofing is an on-link
attack — it can't be launched from outside the broadcast domain, so
watching WAN would just be noise. LAN interfaces are derived at startup
(detect_lan_interfaces()) rather than hardcoded, so this holds regardless
of what the bridge/uplink happen to be named, and generalizes past a
single flat LAN to multiple LAN segments (guest network, VLANs, etc.),
each checked independently.

The OS's ARP cache (`ip neigh`) is used twice: once at startup to seed
bindings instead of learning cold, and again periodically while running,
so the detector doesn't rely solely on catching every relevant packet
itself. Both the startup seed and the periodic re-scan feed the exact
same trust pipeline as a sniffed reply (`_observe`) — a cache entry isn't
treated as more or less authoritative than a live packet, it's just
another way of learning "this IP claims this MAC." That consistency is
what avoids reopening the overwrite bug: a periodic re-scan can't silently
promote an attacker's claim into the trusted binding any more than a
sniffed packet can.

Trusted bindings are never overwritten by a conflicting claim — the first
validated MAC for an IP stays authoritative permanently, the same way the
router's own identity is fixed truth. This is what makes repeated alerts
possible: an attacker's claim never becomes the new baseline, so a
sustained spoof keeps producing signal instead of going quiet after one
alert. Non-gateway mismatches use a State-pattern escalation (mirroring
PortScanDetector's NEW/STRONG/CONTINUED): the first few conflicting
claims are reported as merely suspected, and only once mismatches for the
same (interface, ip) cross `confirm_threshold` does the alert escalate to
confirmed.
"""

import subprocess
from scapy.arch import get_if_addr, get_if_hwaddr
from mantis_eye.core.packet_event import PacketEvent


class ArpSpoofDetector:
    """Alerts when an IP with a known MAC suddenly claims a different one,
    escalating from suspected to confirmed as mismatches accumulate, with
    a dedicated immediate alert for gateway impersonation. Learns from
    both sniffed ARP replies and periodic OS ARP cache re-scans.
    """

    def __init__(self, lan_interfaces: list[str], confirm_threshold: int = 3,
                 resync_interval: int = 60):
        """Seeds two tiers of trust per interface: each interface's own
        (ip -> mac) is pulled directly from the OS and never updated from
        traffic, since it's ground truth. Other hosts are seeded
        best-effort from the OS's existing ARP cache so we aren't starting
        the bindings table empty. `confirm_threshold` is the number of
        conflicting claims for the same (interface, ip) required before an
        alert escalates from suspected to confirmed. `resync_interval` is
        how often (in seconds, measured against packet timestamps) the OS
        ARP cache gets re-checked after startup.
        """
        self.lan_interfaces = lan_interfaces
        self.confirm_threshold = confirm_threshold
        self.resync_interval = resync_interval
        self._last_resync = 0
        self.own_identity: dict[str, tuple[str, str]] = {}  # interface -> (ip, mac)
        self.bindings: dict[tuple[str, str], str] = {}       # (interface, ip) -> mac
        self.mismatch_counts: dict[tuple[str, str], int] = {}  # (interface, ip) -> count

        for iface in lan_interfaces:
            self.own_identity[iface] = (get_if_addr(iface), get_if_hwaddr(iface))
        self._resync_from_neigh_cache()

    def _resync_from_neigh_cache(self):
        """Re-parses `ip neigh show dev <iface>` for every LAN interface and
        feeds each entry through `_observe`, exactly like a sniffed reply.
        Used both at startup (cold seed) and periodically while running
        (catching hosts or changes the sniffer itself may have missed).
        Best-effort per interface: a missing or stale cache for one
        interface doesn't block the others.
        """
        for iface in self.lan_interfaces:
            try:
                output = subprocess.check_output(
                    ["ip", "neigh", "show", "dev", iface], text=True
                )
            except subprocess.CalledProcessError:
                continue

            own_ip, _ = self.own_identity[iface]
            for line in output.splitlines():
                parts = line.split()
                if "lladdr" in parts:
                    ip = parts[0]
                    mac = parts[parts.index("lladdr") + 1]
                    if ip != own_ip:
                        self._observe(iface, ip, mac, dst_mac=None)

    def _observe(self, interface: str, ip: str, mac: str, dst_mac):
        """Core trust logic shared by sniffed ARP replies and cache
        re-scans: checks the gateway identity first, then falls through to
        trust-on-first-use for everyone else. `dst_mac` is only meaningful
        for sniffed packets (who the reply was addressed to) and is `None`
        for cache-derived observations.
        """
        own_ip, own_mac = self.own_identity[interface]

        if ip == own_ip:
            if mac != own_mac:
                self._alert_gateway_spoof(interface, ip, mac, own_mac, dst_mac)
            return

        key = (interface, ip)
        known_mac = self.bindings.get(key)

        if known_mac is None:
            self.bindings[key] = mac
            return

        if known_mac != mac:
            count = self.mismatch_counts.get(key, 0) + 1
            self.mismatch_counts[key] = count

            if count < self.confirm_threshold:
                self._alert_suspected(interface, ip, mac, known_mac, count, dst_mac)
            else:
                self._alert_confirmed(interface, ip, mac, known_mac, count, dst_mac)
            # bindings[key] deliberately NOT updated — known_mac stays the
            # trusted value regardless of the new claim, from either source

    def __call__(self, event: PacketEvent):
        """Feeds a sniffed ARP reply into `_observe`, then, if enough time
        has passed since the last one, triggers a periodic re-scan of the
        OS ARP cache. Only ARP replies (op=2) are trusted to assert a
        binding — requests are broadcast queries and don't claim "I am
        this IP" the way a reply does.
        """
        if event.arp_op != 2 or event.interface not in self.own_identity:
            return

        self._observe(event.interface, event.src_ip, event.src_mac, event.dst_mac)

        if event.timestamp - self._last_resync > self.resync_interval:
            self._resync_from_neigh_cache()
            self._last_resync = event.timestamp

    def _alert_gateway_spoof(self, interface, ip, mac, own_mac, dst_mac):
        """Prints a high-confidence alert: someone is claiming this
        interface's own IP with a MAC that isn't the router's. Immediate,
        not escalated — the router's identity is fixed ground truth.
        """
        target = f", targeting {dst_mac}" if dst_mac else ""
        print(
            f"[ALERT][GATEWAY SPOOF] {ip} (this router's own IP) is being "
            f"claimed by {mac} on {interface}, expected {own_mac}{target}"
        )

    def _alert_suspected(self, interface, ip, mac, known_mac, count, dst_mac):
        """Prints a low-confidence alert for a conflicting claim that
        hasn't yet crossed `confirm_threshold`.
        """
        target = f", targeting {dst_mac}" if dst_mac else ""
        print(
            f"[ALERT][SUSPECTED] ARP spoof on {interface}: "
            f"{ip} was {known_mac}, now claimed by {mac} "
            f"({count}/{self.confirm_threshold} conflicts{target})"
        )

    def _alert_confirmed(self, interface, ip, mac, known_mac, count, dst_mac):
        """Prints a high-confidence alert once conflicts for the same
        (interface, ip) have crossed `confirm_threshold`. Keeps firing on
        every further conflict — an ongoing attack should keep producing
        signal, not go quiet after the first confirmation.
        """
        target = f", targeting {dst_mac}" if dst_mac else ""
        print(
            f"[ALERT][CONFIRMED] ARP spoof on {interface}: "
            f"{ip} was {known_mac}, now claimed by {mac} "
            f"({count} conflicts{target})"
        )