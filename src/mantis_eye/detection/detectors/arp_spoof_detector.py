"""ArpSpoofDetector — detects ARP spoofing and gateway impersonation on the
LAN. Three trust tiers (own identity > DHCP > passive multi-proto) decide
whose claim to believe. Four detection checks run per packet (gateway
impersonation, host impersonation, and two cache-poisoned checks), reporting
under seven check names. Each escalates a shared ArpSpoofAttack keyed on
(interface, attacker_mac, victim_mac), so evidence from different checks
against the same pair accumulates into one incident instead of fragmenting.
_check_new_binding is not a detection: it learns bindings for IPs not yet
trusted. See decisions-and-principles for full design rationale.
"""

import time
import subprocess
import ipaddress
from scapy.arch import get_if_addr, get_if_hwaddr

from mantis_eye.core.packet_event import PacketEvent
from mantis_eye.detection.attacks import Attack, ArpSpoofAttack
from mantis_eye.netinfo.interfaces import get_interface_network
from mantis_eye.netinfo.dhcp import find_dhcp_lease_file
from mantis_eye.detection.detectors.detector import Detector


class ArpSpoofDetector(Detector):
    """Detects ARP spoofing and gateway impersonation per LAN interface.

    Keeps three kinds of state: own_identity (the router's own IP and MAC,
    seeded from the OS and never learned from traffic), bindings (the trusted
    IP-to-MAC map, filled by DHCP leases or by passive learning), and
    pending_state (candidates still being counted toward a binding). Every
    packet and every neighbor-cache entry goes through _run_checks. Incidents
    live in the base class's incidents dict, one ArpSpoofAttack per
    (interface, attacker_mac, victim_mac)."""

    def __init__(self, lan_interfaces, confirm_threshold=3, learn_threshold=3,
                 idle_expiry=300, resync_interval=30, cleanup_interval=60):
        """Seed own_identity unconditionally from the OS for each LAN
        interface (never updated from traffic afterward — see
        _check_gateway_impersonation, which relies on this being ground truth),
        resolve each interface's network for matching DHCP leases to the
        right interface, then run an initial resync so bindings aren't
        empty on the very first packet. The incidents dict comes from the
        Detector base class.

        Args:
            lan_interfaces: Interfaces watched; events on any other interface
                are ignored.
            confirm_threshold: Packets at which a claim-only incident is
                confirmed (gateway ARP claims and host impersonation).
                Observed facts such as cache poisoning confirm immediately.
            learn_threshold: Packets a candidate MAC needs before
                _resolve_pending decides who owns an unbound IP.
            idle_expiry: Seconds of inactivity before an incident decays, and
                before a pending candidate's count restarts.
            resync_interval: Minimum seconds between resyncs from DHCP leases
                and the OS neighbor cache.
            cleanup_interval: Minimum seconds between decay sweeps. Idle
                attacks decay rather than being deleted.
        """
        super().__init__("ARP spoof")
        self.lan_interfaces = lan_interfaces
        self.confirm_threshold = confirm_threshold
        self.learn_threshold = learn_threshold
        self.idle_expiry = idle_expiry
        self.resync_interval = resync_interval
        self._last_resync = 0
        self.cleanup_interval = cleanup_interval
        self._last_cleanup = 0

        self.own_identity = {}       # iface -> (own_ip, own_mac), OS-seeded, never updated from traffic
        self.bindings = {}           # (iface, ip) -> mac, the trusted binding (DHCP or resolved passive)
        self.pending_state = {}      # (iface, ip, mac) -> {"count", "last_seen"}, trust-on-first-use candidates
        self._interface_networks = {}  # iface -> ipaddress network, used to match DHCP leases to interfaces

        for iface in lan_interfaces:
            self.own_identity[iface] = (get_if_addr(iface), get_if_hwaddr(iface))
            network = get_interface_network(iface)
            if network is not None:
                self._interface_networks[iface] = network

        self._resync_all()

    def _resync_all(self):
        """Run both resync sources in order: DHCP leases first (authoritative,
        overwrites passive bindings immediately), then the OS neighbor cache
        (passive, only fills in what DHCP didn't already resolve or
        surfaces conflicts against it — _check_host_impersonation)."""
        self._resync_from_dhcp_leases()
        self._resync_from_neigh_cache()

    def _resync_from_dhcp_leases(self):
        """Read the dnsmasq lease file (if found) and apply each lease as an
        authoritative binding, matching each lease's IP to the correct LAN
        interface by subnet membership rather than assuming a single
        interface, since multiple LAN segments are supported independently.
        """
        path = find_dhcp_lease_file()

        if path is None:
            return

        try:
            with open(path) as f:
                lines = f.readlines()

        except OSError:
            return

        for line in lines:
            parts = line.split()
            if len(parts) < 3:
                continue
            mac, ip = parts[1], parts[2]
            for iface, network in self._interface_networks.items():
                if ipaddress.ip_address(ip) in network:
                    self._apply_authoritative(iface, ip, mac)
                    break

    def _apply_authoritative(self, interface, ip, mac):
        """Apply a DHCP lease as an authoritative binding, overwriting any
        passive binding immediately (no packet count needed, since DHCP is
        trusted outright). The router's own IP is never overwritten this
        way — see own_identity. If this MAC previously held a different IP
        (e.g. reassigned by DHCP), that stale entry is removed so one MAC
        is never trusted under two IPs at once.
        """

        own_ip, _ = self.own_identity[interface]

        if ip == own_ip:
            return  # never let DHCP override our own seeded identity

        key = (interface, ip)
        if self.bindings.get(key) == mac:
            return  # already trusted as-is, nothing to update

        # this MAC may have held a different IP before (e.g. DHCP reassignment) —
        # drop those stale entries so one MAC can't be trusted under two IPs at once
        stale_keys = [k for k, v in self.bindings.items() if k[0] == interface and v == mac and k != key]
        for sk in stale_keys:
            del self.bindings[sk]

        self.bindings[key] = mac  # DHCP is authoritative: overwrite immediately, no packet count needed

    def _resync_from_neigh_cache(self):
        """Periodic sync from the OS's ARP (neighbor) cache into _run_checks.

        Two purposes: (1) helps new bindings reach learn_threshold faster
        than live traffic alone might, since every resync cycle re-feeds
        current entries; (2) catches a cache poisoned before this detector
        started watching, or during a gap between cycles — an entry that
        conflicts with an already-trusted binding is compared against that
        trusted state on every cycle, not just at first observation, so it
        still trips _check_host_impersonation even though it arrived via the
        OS cache rather than a live packet (dst_mac is unknown here, so
        only the general host_impersonation path can fire, never
        host_impersonation_router_targeted, which needs a real packet destination).

        The router's own IP is skipped rather than fed through _run_checks —
        this only protects own_identity from ever being treated as a
        learned binding; it does not itself check whether the cache's
        mapping for the router's own IP is correct.
        """

        now = time.time()

        for iface in self.lan_interfaces:

            try:
                output = subprocess.check_output(["ip", "neigh", "show", "dev", iface], text=True)

            except subprocess.CalledProcessError:
                continue

            own_ip, _ = self.own_identity[iface]

            for line in output.splitlines():
                parts = line.split()
                if "lladdr" in parts:
                    ip = parts[0]
                    mac = parts[parts.index("lladdr") + 1]
                    if ip != own_ip:
                        self._run_checks(iface, ip, mac, None, None, "arp", now)

    def _run_checks(self, interface, src_ip, src_mac, dst_ip, dst_mac, proto, timestamp):
        """Run every applicable detection check against one packet's (or
        neighbor-cache entry's) claim, in a fixed order.

        Checks are not mutually exclusive: a single packet can trigger more
        than one, since the two cache-poisoned checks test dst-based fields
        while the impersonation checks test src-based fields. Two short
        circuits apply. If _check_gateway_impersonation fires (the source
        claims the router's IP with the wrong MAC), that fully explains the
        packet and nothing else runs. If _check_new_binding reports the source
        IP is not yet bound, the packet feeds trust-on-first-use learning and
        _check_host_impersonation is skipped, since a brand-new IP can't
        conflict with anything.

        Args:
            interface: Interface the packet or cache entry came from.
            src_ip, src_mac: The claim being checked (ARP psrc/hwsrc, or the
                packet's source).
            dst_ip, dst_mac: The destination, or None for neighbor-cache
                entries, which have no real destination.
            proto: "arp", "tcp" or "udp"; sets evidence strength for gateway
                claims.
            timestamp: Capture time, or now for cache entries.
        """

        own_ip, own_mac = self.own_identity[interface]

        if self._check_gateway_impersonation(interface, src_ip, src_mac, dst_mac, proto, timestamp, own_ip, own_mac):
            return

        self._check_hosts_router_cache_poisoned(interface, src_ip, src_mac, dst_ip, dst_mac, timestamp, own_ip, own_mac)

        self._check_hosts_host_cache_poisoned(interface, src_mac, dst_ip, dst_mac, timestamp, own_mac)

        if self._check_new_binding(interface, src_ip, src_mac, timestamp):
            return

        self._check_host_impersonation(interface, src_ip, src_mac, dst_mac, timestamp, own_mac)

    def _check_gateway_impersonation(self, interface, src_ip, src_mac, dst_mac, proto, timestamp, own_ip, own_mac):
        """Detect a sender claiming to be the router itself with the wrong
        MAC. Attacker is src_mac; victim is dst_mac, or "broadcast" when the
        claim went to every host (recorded as gateway_impersonation_broadcast
        instead of gateway_impersonation).

        Evidence strength depends on protocol: an ARP announcement is only a
        claim, so it confirms once the incident has seen confirm_threshold
        packets, counting this one (attack.count is read before record()
        increments it, hence the +1). A TCP/UDP packet can only exist if
        something holds the router's IP and relays traffic, which is direct
        proof of interception, so it is floored at "confirmed" on first sight.

        Returns:
            True only when src_ip is the router's IP and src_mac is not the
            router's own MAC: the packet is fully explained and
            _run_checks stops. False otherwise, including for the router's
            own genuine packets.
        """

        if src_ip != own_ip:
            return False

        if src_mac != own_mac:
            is_broadcast = dst_mac == Attack._BROADCAST_MAC
            victim_mac = "broadcast" if is_broadcast else (dst_mac or "unknown")
            attack = self._get_attack(interface, src_mac, victim_mac, timestamp)
            check_name = "gateway_impersonation_broadcast" if is_broadcast else "gateway_impersonation"
            detail = (
                f"claimed gateway IP {src_ip} via broadcast (all hosts on segment targeted)"
                if is_broadcast else
                f"claimed gateway IP {src_ip} via {proto}"
            )
            if proto in ("tcp", "udp"):
                min_status = "confirmed"
            else:
                min_status = "confirmed" if attack.count + 1 >= self.confirm_threshold else None

            attack.record(check_name, timestamp, detail=detail,
                          claimed_ip=src_ip, min_status=min_status)
            self._alert(attack, check_name)
            return True

        return False

    def _check_host_impersonation(self, interface, src_ip, src_mac, dst_mac, timestamp, own_mac):
        """Detect a claim that conflicts with an already-trusted binding.
        Attacker is src_mac. A single mismatch is ambiguous (no
        direct-observation proof), so the attack confirms by count: once this
        packet brings the incident to confirm_threshold (the +1 accounts for
        record() not having run yet).

        Evidence is stronger when the claim is unicast directly to the
        router's own MAC (deliberate targeting). That case is recorded as
        host_impersonation_router_targeted with the router's MAC as victim;
        otherwise it is host_impersonation with the real owner as victim.
        Both use the same escalation.
        """

        known_mac = self.bindings[(interface, src_ip)]

        if known_mac == src_mac:
            return

        # Unicast directly to the router's own MAC is deliberate targeting,
        # stronger evidence than a general/broadcast conflict.
        if dst_mac == own_mac:
            victim_mac, check_name = own_mac, "host_impersonation_router_targeted"
        else:
            victim_mac, check_name = known_mac, "host_impersonation"

        attack = self._get_attack(interface, src_mac, victim_mac, timestamp)
        min_status = "confirmed" if attack.count + 1 >= self.confirm_threshold else None
        attack.record(check_name, timestamp,
                      detail=f"conflicting claim on {src_ip} (known owner {known_mac})",
                      claimed_ip=src_ip, min_status=min_status)
        self._alert(attack, check_name)

    def _check_hosts_router_cache_poisoned(self, interface, src_ip, src_mac, dst_ip, dst_mac, timestamp, own_ip, own_mac):
        """Detect traffic addressed to the router (dst_ip is the router's
        own IP) arriving at the wrong MAC — proof that the sender's own ARP
        cache has been poisoned regarding the router's identity. This is an
        observed fact, not a claim, so it's always floored at "confirmed"
        even the first time it's seen. The MAC that wrongly received the
        packet (dst_mac) is recorded as the attacker and the sender (src_mac)
        as the victim.
        """

        if not (dst_ip == own_ip and dst_mac and dst_mac.lower() != Attack._BROADCAST_MAC and dst_mac != own_mac):
            return

        attack = self._get_attack(interface, dst_mac, src_mac, timestamp)
        attack.record("hosts_router_cache_poisoned", timestamp,
                      detail="victim's cache poisoned re: gateway", min_status="confirmed")
        self._alert(attack, "hosts_router_cache_poisoned")

    def _check_hosts_host_cache_poisoned(self, interface, src_mac, dst_ip, dst_mac, timestamp, own_mac):
        """Detect traffic addressed to any known non-gateway binding
        arriving at the wrong MAC. The MAC that wrongly received it
        (dst_mac) is always the attacker. Two sub-cases: if the sender is the
        router itself, this proves the router's own ARP cache has been
        poisoned — the strongest possible evidence, since it means this
        router is actively misdirecting traffic. It is recorded as
        router_cache_poisoned, with the real owner of the IP as victim. If
        the sender is anyone else, it is recorded as hosts_host_cache_poisoned
        with the sender as victim, proof about that sender's cache instead.
        Both are observed facts and floored at "confirmed" on first sight.
        """

        known_dst_mac = self.bindings.get((interface, dst_ip))

        if not (known_dst_mac is not None and dst_mac and dst_mac.lower() != Attack._BROADCAST_MAC and dst_mac != known_dst_mac):
            return

        if src_mac == own_mac:
            # The router itself sent to the wrong MAC for a known IP — proof
            # this router's own cache was poisoned, the strongest evidence.
            attack = self._get_attack(interface, dst_mac, known_dst_mac, timestamp)
            attack.record("router_cache_poisoned", timestamp,
                          detail=f"router's own cache poisoned re: {dst_ip}",
                          claimed_ip=dst_ip, min_status="confirmed")
            self._alert(attack, "router_cache_poisoned")

        else:
            attack = self._get_attack(interface, dst_mac, src_mac, timestamp)
            attack.record("hosts_host_cache_poisoned", timestamp,
                          detail=f"victim's cache poisoned re: {dst_ip}",
                          claimed_ip=dst_ip, min_status="confirmed")
            self._alert(attack, "hosts_host_cache_poisoned")

    def _check_new_binding(self, interface, src_ip, src_mac, timestamp):
        """Trust-on-first-use path for an IP with no existing binding yet.
        Rather than trusting the first MAC seen (which an attacker could
        win by racing), claims accumulate in pending_state until
        learn_threshold, at which point _resolve_pending picks the
        highest-volume candidate. Returns True whenever this IP isn't
        bound yet, signaling _run_checks to skip _check_host_impersonation,
        since a not-yet-trusted IP can't have a conflicting claim.
        """

        if (interface, src_ip) in self.bindings:
            return False

        pkey = (interface, src_ip, src_mac)
        count = self._track_count(pkey, timestamp, self.pending_state)

        if count >= self.learn_threshold:
            self._resolve_pending(interface, src_ip)

        return True

    def _track_count(self, key, timestamp, state):
        """Plain counter with idle-expiry reset, used for pending_state
        (trust-on-first-use accumulation toward a binding) only — not
        attack evidence, so it stays a dict rather than an ArpSpoofAttack.
        """
        entry = state.get(key)
        if entry is None or timestamp - entry["last_seen"] > self.idle_expiry:
            count = 1
        else:
            count = entry["count"] + 1
        state[key] = {"count": count, "last_seen": timestamp}
        return count

    def _resolve_pending(self, interface, ip):
        """Once a candidate for (interface, ip) has reached learn_threshold,
        decide which candidate MAC actually owns the IP by packet volume,
        not by which one reached the threshold first — this prevents an
        attacker winning trust simply by racing to speak first. A tie
        between two candidates defers the decision rather than guessing;
        it will resolve once further packets break the tie. On resolution,
        every candidate's pending entry for this IP is cleared, not just
        the winner's, since the contest for this IP is over either way.
        """
        candidates = {k[2]: s["count"] for k, s in self.pending_state.items()
                      if k[0] == interface and k[1] == ip}
        if not candidates:
            return
        best = max(candidates.values())
        winners = [m for m, c in candidates.items() if c == best]
        if len(winners) > 1:
            return
        winning_mac = winners[0]
        self.bindings[(interface, ip)] = winning_mac
        for mac in candidates:
            self.pending_state.pop((interface, ip, mac), None)

    def _get_attack(self, interface, attacker_mac, victim_mac, timestamp):
        """Fetch the existing ArpSpoofAttack for this (interface,
        attacker_mac, victim_mac) triple, or create one if this is the
        first evidence seen against this pair. This is the single point
        where the correlation key is applied, so every _check_* method
        stays consistent without duplicating the key shape.
        """
        key = (interface, attacker_mac, victim_mac)
        attack = self.incidents.get(key)
        if attack is None:
            attack = ArpSpoofAttack(interface, attacker_mac, victim_mac, timestamp,
                                    self.idle_expiry, self.confirm_threshold)
            self.incidents[key] = attack
        return attack

    def __call__(self, event: PacketEvent):
        """Entry point invoked by the Dispatcher for each matching packet.
        Ignores events on interfaces this detector wasn't configured for. The
        time-gated decay sweep runs before the checks, so a packet resuming a
        long-idle attack finds it already decayed and can restore it, instead
        of refreshing last_seen before the sweep looks. Then runs the checks
        through _run_checks, and triggers a resync if resync_interval has
        elapsed. The resync runs after the checks, so the packet that
        triggers it is judged against the bindings from before the resync."""
        if event.interface not in self.own_identity:
            return

        if event.timestamp - self._last_cleanup > self.cleanup_interval:
            self._expire_idle(event.timestamp)
            self._last_cleanup = event.timestamp

        self._run_checks(
            event.interface, event.src_ip, event.src_mac,
            event.dst_ip, event.dst_mac, event.proto, event.timestamp)

        if event.timestamp - self._last_resync > self.resync_interval:
            self._resync_all()
            self._last_resync = event.timestamp