"""ArpSpoofDetector — detects ARP spoofing and gateway impersonation on the
LAN. Three trust tiers (own identity > DHCP > passive multi-proto), five
independent detection checks per packet, each escalating a shared
ArpSpoofAttack instance keyed on (interface, attacker_mac, victim_mac) so
evidence from different checks against the same pair accumulates into one
incident instead of fragmenting. See decisions-and-principles for full
design rationale.
"""

import time
import subprocess
import ipaddress
from scapy.arch import get_if_addr, get_if_hwaddr

from mantis_eye.core.packet_event import PacketEvent
from mantis_eye.detection.attacks import ArpSpoofAttack
from mantis_eye.netinfo.interfaces import get_interface_network
from mantis_eye.netinfo.dhcp import find_dhcp_lease_file

_STATUS_LABELS = {"suspected": "SUSPECTED", "confirmed": "CONFIRMED", "ongoing": "ONGOING"}
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


class ArpSpoofDetector:
    def __init__(self, lan_interfaces, confirm_threshold=3, learn_threshold=3,
                 idle_expiry=300, resync_interval=30):
        """Seed own_identity unconditionally from the OS for each LAN
        interface (never updated from traffic afterward — see
        _check_gateway_identity, which relies on this being ground truth),
        resolve each interface's network for matching DHCP leases to the
        right interface, then run an initial resync so bindings aren't
        empty on the very first packet.
        """
        self.lan_interfaces = lan_interfaces
        self.confirm_threshold = confirm_threshold
        self.learn_threshold = learn_threshold
        self.idle_expiry = idle_expiry
        self.resync_interval = resync_interval
        self._last_resync = 0
        
        self.own_identity = {}       # iface -> (own_ip, own_mac), OS-seeded, never updated from traffic
        self.bindings = {}           # (iface, ip) -> mac, the trusted binding (DHCP or resolved passive)
        self.mismatch_state = {}     # (iface, attacker_mac, victim_mac) -> ArpSpoofAttack, tracked suspicion
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
        surfaces conflicts against it — see _check_binding_conflict)."""
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
        """Periodic sync from the OS's ARP (neighbor) cache into _observe.

        Two purposes: (1) helps new bindings reach learn_threshold faster
        than live traffic alone might, since every resync cycle re-feeds
        current entries; (2) catches a cache poisoned before this detector
        started watching, or during a gap between cycles — an entry that
        conflicts with an already-trusted binding is compared against that
        trusted state on every cycle, not just at first observation, so it
        still trips _check_binding_conflict even though it arrived via the
        OS cache rather than a live packet (dst_mac is unknown here, so
        only the general binding_spoof path can fire, never
        router_targeted, which needs a real packet destination).

        The router's own IP is skipped rather than fed through _observe —
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
                        self._observe(iface, ip, mac, None, None, "arp", now)


    def _observe(self, interface, src_ip, src_mac, dst_ip, dst_mac, proto, timestamp):
        """Run every applicable detection check against one packet's (or
        neighbor-cache entry's) claim. Checks are not mutually exclusive by
        default — a single packet can legitimately trigger more than one,
        since the gateway/host-misdirect checks test dst-based fields while
        the binding checks test src-based fields. The one exception is
        _check_gateway_identity: if the source claims to be the gateway,
        that already fully explains the packet, so remaining checks are
        skipped. Likewise _check_new_binding short-circuits
        _check_binding_conflict, since a brand-new IP can't yet conflict
        with anything.
        """

        own_ip, own_mac = self.own_identity[interface]
        
        if self._check_gateway_identity(interface, src_ip, src_mac, dst_mac, proto, timestamp, own_ip, own_mac):
            return
        
        self._check_gateway_misdirect(interface, src_ip, src_mac, dst_ip, dst_mac, timestamp, own_ip, own_mac)
        
        self._check_host_misdirect(interface, src_mac, dst_ip, dst_mac, timestamp, own_mac)
        
        if self._check_new_binding(interface, src_ip, src_mac, timestamp):
            return
        
        self._check_binding_conflict(interface, src_ip, src_mac, dst_mac, timestamp, own_mac)

    def _check_gateway_identity(self, interface, src_ip, src_mac, dst_mac, proto, timestamp, own_ip, own_mac):
        """Detect a sender claiming to be the router itself with the wrong
        MAC. Evidence strength depends on protocol: an ARP announcement is
        just a claim (could be a mistake or an early attack step), so it
        gets no forced floor and escalates via count alone; a TCP/UDP
        packet can only exist if something actually holds the router's IP
        and is relaying traffic, which is direct proof of active
        interception, so it's floored at "confirmed" even on first sight.
        Returns True whenever src_ip matches the router's own IP (whether
        or not the MAC also matched), signaling _observe that this packet
        is already fully explained and no further checks are needed.
        """

        if src_ip != own_ip:
            return False
        
        if src_mac != own_mac:
            victim_mac = dst_mac or "unknown"
            attack = self._get_attack(interface, src_mac, victim_mac, timestamp)
            # ARP: an announcement is a claim, needs corroboration to escalate.
            # TCP/UDP: only the real gateway could send with its own IP, so
            # this is direct proof of active relay/interception, not a claim.
            min_status = "confirmed" if proto in ("tcp", "udp") else None
            attack.record("gateway_identity", timestamp,
                           detail=f"claimed gateway IP {src_ip} via {proto}",
                           claimed_ip=src_ip, min_status=min_status)
            self._alert(attack, "gateway_identity")
        
        return True

    def _check_gateway_misdirect(self, interface, src_ip, src_mac, dst_ip, dst_mac, timestamp, own_ip, own_mac):
        """Detect traffic addressed to the router (dst_ip is the router's
        own IP) arriving at the wrong MAC — proof that the sender's own ARP
        cache has been poisoned regarding the router's identity. This is an
        observed fact, not a claim, so it's always floored at "confirmed"
        even the first time it's seen.
        """

        if not (dst_ip == own_ip and dst_mac and dst_mac.lower() != _BROADCAST_MAC and dst_mac != own_mac):
            return
        
        attack = self._get_attack(interface, dst_mac, src_mac, timestamp)
        attack.record("gateway_misdirect", timestamp,
                       detail="victim's cache poisoned re: gateway", min_status="confirmed")
        self._alert(attack, "gateway_misdirect")

    def _check_host_misdirect(self, interface, src_mac, dst_ip, dst_mac, timestamp, own_mac):
        """Detect traffic addressed to any known non-gateway binding
        arriving at the wrong MAC. Two sub-cases: if the sender is the
        router itself, this proves the router's own ARP cache has been
        poisoned — the strongest possible evidence, since it means this
        router is actively misdirecting traffic, not just a victim; if the
        sender is anyone else, it's the same kind of proof but about that
        sender's cache instead. Both are observed facts and floored at
        "confirmed" on first sight.
        """

        known_dst_mac = self.bindings.get((interface, dst_ip))
        
        if not (known_dst_mac is not None and dst_mac and dst_mac.lower() != _BROADCAST_MAC and dst_mac != known_dst_mac):
            return
        
        if src_mac == own_mac:
            # The router itself sent to the wrong MAC for a known IP — proof
            # this router's own cache was poisoned, the strongest evidence.
            attack = self._get_attack(interface, dst_mac, known_dst_mac, timestamp)
            attack.record("router_poisoned", timestamp,
                           detail=f"router's own cache poisoned re: {dst_ip}",
                           claimed_ip=dst_ip, min_status="confirmed")
            self._alert(attack, "router_poisoned")
        
        else:
            attack = self._get_attack(interface, dst_mac, src_mac, timestamp)
            attack.record("host_misdirect", timestamp,
                           detail=f"victim's cache poisoned re: {dst_ip}",
                           claimed_ip=dst_ip, min_status="confirmed")
            self._alert(attack, "host_misdirect")

    def _check_new_binding(self, interface, src_ip, src_mac, timestamp):
        """Trust-on-first-use path for an IP with no existing binding yet.
        Rather than trusting the first MAC seen (which an attacker could
        win by racing), claims accumulate in pending_state until
        learn_threshold, at which point _resolve_pending picks the
        highest-volume candidate. Returns True whenever this IP isn't
        bound yet, signaling _observe to skip _check_binding_conflict,
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

    def _check_binding_conflict(self, interface, src_ip, src_mac, dst_mac, timestamp, own_mac):
        """Detect a claim that conflicts with an already-trusted binding.
        Unlike the misdirect checks, a single mismatch here is genuinely
        ambiguous (no direct-observation proof), so no min_status is
        forced — it escalates via count alone. Evidence is stronger when
        the conflicting claim is unicast directly to the router's own MAC
        (deliberate targeting) than a general/broadcast conflict, so the
        two cases are recorded under different check names and victim
        identities for reporting purposes, even though both use the same
        escalation path.
        """
        
        known_mac = self.bindings[(interface, src_ip)]
        
        if known_mac == src_mac:
            return
        # Unicast directly to the router's own MAC is deliberate targeting,
        # stronger evidence than a general/broadcast conflict.
        
        if dst_mac == own_mac:
            victim_mac, check_name = own_mac, "router_targeted"
        
        else:
            victim_mac, check_name = known_mac, "binding_spoof"
        
        attack = self._get_attack(interface, src_mac, victim_mac, timestamp)
        attack.record(check_name, timestamp,
                       detail=f"conflicting claim on {src_ip} (known owner {known_mac})",
                       claimed_ip=src_ip)
        self._alert(attack, check_name)

    def _get_attack(self, interface, attacker_mac, victim_mac, timestamp):
        """Fetch the existing ArpSpoofAttack for this (interface,
        attacker_mac, victim_mac) triple, or create one if this is the
        first evidence seen against this pair. This is the single point
        where the correlation key is applied, so every _check_* method
        stays consistent without duplicating the key shape.
        """
        key = (interface, attacker_mac, victim_mac)
        attack = self.mismatch_state.get(key)
        if attack is None:
            attack = ArpSpoofAttack(interface, attacker_mac, victim_mac, timestamp,
                                        self.idle_expiry, self.confirm_threshold)
            self.mismatch_state[key] = attack
        return attack


    def _alert(self, attack, check_name):
        """Print a single alert line for the given attack's current state.
        Every _check_* method funnels through here after recording
        evidence, so an attack's alert always reflects its full correlated
        history (count, claimed_ips) rather than just the triggering check.
        """

        label = _STATUS_LABELS[attack.status]
        print(f"[{label}] ARP attack: {attack.attacker_mac} -> {attack.victim_mac} "
              f"on {attack.interface} (count={attack.count}, triggered by {check_name}, "
              f"claimed_ips={attack.claimed_ips})")

    def __call__(self, event: PacketEvent):
        """Entry point invoked by the Dispatcher for each matching packet.
        Ignores events on interfaces this detector wasn't configured for,
        runs the full observation pipeline, then triggers a resync if
        resync_interval has elapsed since the last one.
        """
        if event.interface not in self.own_identity:
            return
        
        self._observe(event.interface, event.src_ip, event.src_mac,
                       event.dst_ip, event.dst_mac, event.proto, event.timestamp)
        
        if event.timestamp - self._last_resync > self.resync_interval:
            self._resync_all()
            self._last_resync = event.timestamp