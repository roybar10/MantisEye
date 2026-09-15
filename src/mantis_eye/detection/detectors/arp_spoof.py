"""Detects ARP spoofing and gateway impersonation on the LAN by watching
for IP<->MAC binding changes across ALL traffic, not just ARP packets.

Scoped to LAN-facing interfaces only, since this class of attack is
on-link — it can't be launched from outside the broadcast domain, so
watching WAN would just be noise. LAN interfaces should be passed in via
detect_lan_interfaces() rather than hardcoded, so this holds regardless of
what the bridge/uplink happen to be named, and generalizes past a single
flat LAN to multiple LAN segments (guest network, VLANs, etc.), each
checked independently with interface-scoped keys.

Scope assumption (see README): MantisEye targets a home/small-office
router where the router itself runs DHCP (dnsmasq). The local lease file
is auto-discovered (checked at known default paths) rather than passed
in. Enterprise topologies with a separate DHCP server are out of scope —
the correct extension there is sniffing DHCPACK traffic trusting only a
configured server IP, not SSH/API access to a remote DHCP server, which
would add a stored-credential attack surface to the IDS itself.

Trust comes from three tiers, ranked by authority:

1. Own identity — each interface's own (ip, mac), pulled directly from the
   OS at startup and never updated from ANY source. Unconditional ground
   truth.
2. DHCP leases (authoritative) — read from the router's local dnsmasq
   lease file, matched to a tracked interface by subnet membership. CAN
   overwrite an existing passive binding immediately, with no packet
   count required, because it's a fact the router generated. Applied
   before the passive resync each cycle so a genuine reassignment is
   corrected before the passive tier would otherwise flag it as a
   mismatch. When a device's IP changes, any other binding entry still
   pointing at that same MAC is removed (a device only holds one IP at a
   time) via a linear scan — acceptable at home-router scale.
3. Passive, multi-proto observation — EVERY packet (ARP, TCP, UDP; not
   just ARP replies) carries a sender IP+MAC assertion, since an
   attacker can forge a request as easily as a reply, and normal TCP/UDP
   traffic asserts the same claim implicitly via its headers. A
   never-before-seen IP doesn't get trusted on the first packet: it
   accumulates in `pending_state` until `learn_threshold` packets are
   seen, at which point `_resolve_pending` compares ALL competing
   candidates for that IP and promotes whichever sent the most packets —
   not whichever merely crossed the threshold first — since traffic
   volume is a reasonable proxy for legitimacy, and it prevents a fast
   attacker from winning trust purely by racing to speak first. Ties
   defer promotion rather than guess. Once a binding is trusted, it is
   NEVER overwritten by a later conflicting claim (only tier 2 can do
   that) — conflicts instead escalate through suspected -> confirmed ->
   ongoing (State pattern, mirrors PortScanDetector's
   NEW/STRONG/CONTINUED), tracked in `mismatch_state`, decaying after
   idle_expiry of inactivity for that specific key. This decay is the
   ONLY mechanism that reduces suspicion — DHCP confirming or reassigning
   an IP never resets it, since an unchanged or changed lease carries no
   information about whether a past or ongoing attack has stopped.

Tracking keys are anchored to MAC identities, not IP, wherever the thing
being tracked is "who is attacking" rather than "which IP is disputed" —
IP is exactly the thing that can legitimately change (via DHCP, or a
victim's own address changing) without the attack having stopped.

Gateway impersonation is tracked from THREE angles, all feeding the same
(interface, attacker_mac, victim_mac) key since they're evidence of one
attack observed from different vantage points:
- An ARP/cache packet directly claims the router's own IP with the wrong
  MAC (an announcement — proof someone is claiming the identity).
- A genuine TCP/UDP packet that only the router could have sent (its own
  src_ip) arrives via a MAC that isn't the router's (a relay — proof an
  attacker is already actively intercepting traffic, since the router
  itself always sends with its correct MAC).
- Traffic addressed TO the router's own IP arrives at a MAC that isn't
  the router's (a misdirect — proof the SENDER's ARP cache is poisoned,
  observed from the victim's side rather than the attacker's).

DHCP and the passive ARP cache are resynced together, DHCP first, and any
disagreement between them is itself treated as detection evidence rather
than silently reconciled — the passive resync still runs `_observe`
against whatever DHCP just established, so a stale or actively-poisoned
OS cache entry that contradicts a fresh DHCP lease raises a suspected
alert even though DHCP's value is what stays trusted.

Known open gap: on interfaces with neither DHCP nor static ARP entries,
a legitimate but never-corroborated reassignment can still look identical
to a slow, low-volume attack during the pending/mismatch accumulation
window. Active ARP challenge-response probing was designed as a further
mitigation but is not implemented.
"""

import os
import time
import subprocess
import ipaddress
from scapy.arch import get_if_addr, get_if_hwaddr
from mantis_eye.core.packet_event import PacketEvent

_STATUS_LABELS = {"suspected": "SUSPECTED", "confirmed": "CONFIRMED", "ongoing": "ONGOING"}
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

_DHCP_LEASE_CANDIDATES = [
    "/var/lib/misc/dnsmasq.leases",  # Debian/Ubuntu default
    "/var/lib/dhcp/dnsmasq.leases",
    "/tmp/dnsmasq.leases",            # OpenWrt / embedded
]


class ArpSpoofDetector:
    """Alerts on ARP spoofing and gateway impersonation, escalating from
    suspected to confirmed to ongoing as detections accumulate, and
    requiring a minimum amount of corroborating traffic before trusting a
    new IP<->MAC binding at all. Learns from every proto's sender fields,
    periodic OS ARP cache re-scans, and the router's local DHCP leases.
    """

    def __init__(self, lan_interfaces: list[str], confirm_threshold: int = 3,
                 learn_threshold: int = 3, idle_expiry: int = 300,
                 resync_interval: int = 30):
        """Seeds identity and subnet info per interface, then runs an
        initial resync. `confirm_threshold` is how many detections for the
        same tracking key escalate suspected -> confirmed. `learn_threshold`
        is how many packets a never-before-seen IP's candidate MAC needs
        before it can be trusted at all. `idle_expiry` (seconds) resets a
        key's accumulated count if it's gone quiet that long. `resync_interval`
        (seconds, measured against packet timestamps) controls how often
        DHCP leases and the passive cache get re-checked after startup.
        """
        self.lan_interfaces = lan_interfaces
        self.confirm_threshold = confirm_threshold
        self.learn_threshold = learn_threshold
        self.idle_expiry = idle_expiry
        self.resync_interval = resync_interval
        self._last_resync = 0

        self.own_identity: dict[str, tuple[str, str]] = {}          # interface -> (ip, mac)
        self.bindings: dict[tuple[str, str], str] = {}               # (interface, ip) -> mac
        self.mismatch_state: dict[tuple, dict] = {}                   # key -> {"count", "last_seen"}
        self.pending_state: dict[tuple, dict] = {}                    # (interface, ip, candidate_mac) -> {"count", "last_seen"}
        self._interface_networks: dict[str, ipaddress.IPv4Network] = {}

        for iface in lan_interfaces:
            self.own_identity[iface] = (get_if_addr(iface), get_if_hwaddr(iface))
            network = self._get_interface_network(iface)
            if network is not None:
                self._interface_networks[iface] = network

        self._resync_all()

    def _get_interface_network(self, iface: str):
        """Returns the interface's subnet via `ip -o -4 addr show`, used to
        match a DHCP lease's IP to the tracked interface it belongs to —
        dnsmasq writes all leases to one shared file regardless of which
        interface/range actually issued them.
        """
        try:
            output = subprocess.check_output(
                ["ip", "-o", "-4", "addr", "show", "dev", iface], text=True
            )
            cidr = output.split()[3]  # e.g. "10.0.0.254/24"
            return ipaddress.ip_interface(cidr).network
        except (subprocess.CalledProcessError, IndexError, ValueError):
            return None

    def _resync_all(self):
        """Re-checks trust sources, strongest first: DHCP leases, then the
        passive ARP cache. DHCP must run first and apply silently, so a
        legitimate reassignment it already knows about is reflected in
        `bindings` before the passive pass runs. Any disagreement the
        passive pass then finds against what DHCP just established is
        itself treated as detection evidence, not silently discarded.
        """
        self._resync_from_dhcp_leases()
        self._resync_from_neigh_cache()

    def _resync_from_dhcp_leases(self):
        """Reads the auto-discovered dnsmasq lease file (if found) and
        applies each lease to whichever tracked interface's subnet
        contains it, via `_apply_authoritative`. No lease file, or a lease
        outside every tracked subnet, is not an error — that interface or
        entry just stays on passive-only trust.
        """
        path = self._find_dhcp_lease_file()
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
            mac, ip = parts[1], parts[2]  # dnsmasq.leases: <expiry> <mac> <ip> <hostname> <client_id>
            for iface, network in self._interface_networks.items():
                if ipaddress.ip_address(ip) in network:
                    self._apply_authoritative(iface, ip, mac)
                    break

    def _find_dhcp_lease_file(self):
        """Searches known default dnsmasq lease file locations and returns
        the first that exists. Auto-discovered rather than configured, so
        nothing external needs to know dnsmasq's file layout.
        """
        for path in _DHCP_LEASE_CANDIDATES:
            if os.path.exists(path):
                return path
        return None

    def _apply_authoritative(self, interface: str, ip: str, mac: str):
        """Applies a ground-truth binding from DHCP, overwriting the
        trusted MAC immediately (no packet count required) when it
        changes. Also removes any other (interface, ip) binding currently
        pointing to the same mac, since a device only holds one IP at a
        time. A linear scan over bindings; fine at home-router scale.
        Deliberately never touches mismatch_state or pending_state:
        suspicion only ever fades via idle_expiry, and an already-trusted
        candidate's suspicion isn't DHCP's to clear.
        """
        own_ip, _ = self.own_identity[interface]
        if ip == own_ip:
            return
        key = (interface, ip)
        if self.bindings.get(key) == mac:
            return  # already correct, nothing to do

        stale_keys = [k for k, v in self.bindings.items()
                        if k[0] == interface and v == mac and k != key]
        for stale_key in stale_keys:
            del self.bindings[stale_key]

        self.bindings[key] = mac

    def _resync_from_neigh_cache(self):
        """Re-parses `ip neigh show dev <iface>` for every LAN interface and
        feeds each entry through `_observe`, same as a sniffed packet's
        sender fields. Cache entries have no destination or proto concept
        of their own, so `dst_ip`/`dst_mac` are `None` and `proto` is
        reported as "arp" (the OS's neighbor table is itself
        ARP-resolution data). Uses wall-clock time since a cache entry
        has no packet timestamp. Best-effort per interface.
        """
        now = time.time()
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
                        self._observe(iface, ip, mac, dst_ip=None, dst_mac=None,
                                      proto="arp", timestamp=now)


    def _observe(self, interface: str, src_ip: str, src_mac: str,
                dst_ip, dst_mac, proto: str, timestamp: float):
            """The single shared trust decision for every packet, regardless of
            proto. Delegates to one method per check — see each method's
            docstring for what it detects. See the module docstring for the full
            trust-tier rationale.
            """
            own_ip, own_mac = self.own_identity[interface]

            if self._check_gateway_identity(interface, src_ip, src_mac, dst_mac, proto, timestamp, own_ip, own_mac):
                return

            self._check_gateway_misdirect(interface, src_ip, src_mac, dst_ip, dst_mac, timestamp, own_ip, own_mac)

            self._check_host_misdirect(interface, src_mac, dst_ip, dst_mac, timestamp, own_mac)

            if self._check_new_binding(interface, src_ip, src_mac, timestamp):
                return

            self._check_binding_conflict(interface, src_ip, src_mac, dst_mac, timestamp, own_mac)

    def _track_count(self, key: tuple, timestamp: float, state: dict) -> int:
        """Generic accumulate-with-decay counter shared by mismatch
        tracking (earning suspicion) and pending-binding tracking (earning
        trust) — identical mechanics, different meaning per caller. Resets
        to 1 if `idle_expiry` has elapsed since the last hit for this key.
        """
        entry = state.get(key)
        if entry is None or timestamp - entry["last_seen"] > self.idle_expiry:
            count = 1
        else:
            count = entry["count"] + 1
        state[key] = {"count": count, "last_seen": timestamp}
        return count

    def _status_for(self, count: int) -> str:
        """Maps a count against confirm_threshold to a status label."""
        if count < self.confirm_threshold:
            return "suspected"
        elif count == self.confirm_threshold:
            return "confirmed"
        return "ongoing"

    def _resolve_pending(self, interface: str, ip: str):
        """Once any candidate MAC for a never-before-seen IP crosses
        learn_threshold, compares ALL currently pending candidates for
        that IP and promotes whichever has sent the most packets — not
        simply whichever crossed the threshold first. This matters when
        multiple sources claim the same new IP simultaneously (a real
        device and an attacker racing to be trusted first): packet volume
        is a reasonable proxy for legitimacy. A tie means the evidence
        doesn't distinguish them yet, so promotion is deferred. A losing
        candidate isn't discarded — its next packet after promotion lands
        in the normal conflict path and starts accumulating suspicion.
        """
        candidates = {
            key[2]: state["count"]
            for key, state in self.pending_state.items()
            if key[0] == interface and key[1] == ip
        }
        if not candidates:
            return

        best_count = max(candidates.values())
        winners = [mac for mac, count in candidates.items() if count == best_count]
        if len(winners) > 1:
            return  # tie — inconclusive, wait for more data

        winning_mac = winners[0]
        self.bindings[(interface, ip)] = winning_mac
        for mac in candidates:
            self.pending_state.pop((interface, ip, mac), None)

    def _check_gateway_identity(self, interface, src_ip, src_mac, dst_mac,
                             proto, timestamp, own_ip, own_mac) -> bool:
        """Checks: does the sender claim to be the router with the wrong MAC?
        An ARP announcement of a false identity, or (for TCP/UDP, which only
        the real router could have sent) direct proof of active relaying.
        Returns True if this check applied at all (caller should stop, since
        the router's own identity is never subject to the checks below).
        """
        if src_ip != own_ip:
            return False

        if src_mac != own_mac:
            key = (interface, src_mac, dst_mac or "unknown")
            count = self._track_count(key, timestamp, self.mismatch_state)
            if proto in ("tcp", "udp"):
                status = "ongoing" if count > 1 else "confirmed"
                self._alert_gateway_relay(interface, src_ip, src_mac, own_mac, proto, count, status)
            else:
                status = self._status_for(count)
                self._alert_gateway_spoof(interface, src_ip, src_mac, own_mac, dst_mac, count, status)
        return True
        
    def _check_gateway_misdirect(self, interface, src_ip, src_mac, dst_ip, dst_mac,
                              timestamp, own_ip, own_mac):
        """Checks: did traffic addressed to the router's own IP arrive at a
        MAC that isn't the router's? Proof the SENDER's ARP cache is
        poisoned about the router — observed from the victim's side.
        """
        if not (dst_ip == own_ip and dst_mac
                and dst_mac.lower() != _BROADCAST_MAC and dst_mac != own_mac):
            return

        key = (interface, dst_mac, src_mac)  # attacker_mac, victim_mac
        count = self._track_count(key, timestamp, self.mismatch_state)
        status = "ongoing" if count > 1 else "confirmed"
        self._alert_gateway_misdirect(interface, src_mac, dst_mac, own_mac, count, status)

    def _check_host_misdirect(self, interface, src_mac, dst_ip, dst_mac, timestamp, own_mac):
        """Checks: did traffic addressed to a known (non-gateway) host arrive
        at a MAC that isn't that host's trusted MAC? If the sender is this
        router itself, that's proof THIS router's own cache was poisoned;
        otherwise it's proof the SENDER's cache is poisoned about that host.
        """
        known_dst_mac = self.bindings.get((interface, dst_ip))
        if not (known_dst_mac is not None and dst_mac
                and dst_mac.lower() != _BROADCAST_MAC and dst_mac != known_dst_mac):
            return

        if src_mac == own_mac:
            key = (interface, dst_mac, known_dst_mac)  # attacker_mac, victim_mac
            count = self._track_count(key, timestamp, self.mismatch_state)
            status = "ongoing" if count > 1 else "confirmed"
            self._alert_router_poisoned(interface, dst_ip, dst_mac, known_dst_mac, count, status)
        else:
            key = (interface, dst_mac, src_mac)  # attacker_mac, victim_mac
            count = self._track_count(key, timestamp, self.mismatch_state)
            status = "ongoing" if count > 1 else "confirmed"
            self._alert_host_misdirect(interface, dst_ip, src_mac, dst_mac, known_dst_mac, count, status)

    def _check_new_binding(self, interface, src_ip, src_mac, timestamp) -> bool:
        """Checks: is this IP never-before-seen? Accumulates the candidate
        MAC in pending_state until learn_threshold, then resolves the
        highest-volume candidate into a trusted binding. Returns True if this
        IP had no trusted binding yet (caller should stop — nothing to
        compare a conflict against).
        """
        if (interface, src_ip) in self.bindings:
            return False

        pkey = (interface, src_ip, src_mac)
        count = self._track_count(pkey, timestamp, self.pending_state)
        if count >= self.learn_threshold:
            self._resolve_pending(interface, src_ip)
        return True   

    def _check_binding_conflict(self, interface, src_ip, src_mac, dst_mac, timestamp, own_mac):
        """Checks: is an already-trusted IP now claimed by a different MAC?
        If the conflicting claim is addressed directly to this router (unicast
        to own_mac), that's the router itself being specifically targeted;
        otherwise it's a general spoofing conflict against any other listener.
        """
        known_mac = self.bindings[(interface, src_ip)]
        if known_mac == src_mac:
            return

        if dst_mac == own_mac:
            akey = (interface, src_mac, src_ip)  # attacker_mac, targeted_ip
            count = self._track_count(akey, timestamp, self.mismatch_state)
            status = self._status_for(count)
            self._alert_router_targeted(interface, src_ip, src_mac, known_mac, count, status)
        else:
            mkey = (interface, src_ip, src_mac)
            count = self._track_count(mkey, timestamp, self.mismatch_state)
            status = self._status_for(count)
            self._alert_binding_spoof(interface, src_ip, src_mac, known_mac, count, status, dst_mac)


    def __call__(self, event: PacketEvent):
        """Feeds every packet's sender (and, where relevant, destination)
        fields into `_observe`, regardless of proto — TCP/UDP traffic
        asserts the same "I am this IP, at this MAC" claim ARP does, just
        implicitly via its headers rather than explicitly, and this both
        speeds up reaching learn_threshold and strengthens gateway-relay
        detection. Then, if enough time has passed, triggers a periodic
        resync of DHCP leases and the passive ARP cache.
        """
        if event.interface not in self.own_identity:
            return

        self._observe(event.interface, event.src_ip, event.src_mac,
                       event.dst_ip, event.dst_mac, event.proto, event.timestamp)

        if event.timestamp - self._last_resync > self.resync_interval:
            self._resync_all()
            self._last_resync = event.timestamp

    def _alert_gateway_spoof(self, interface, ip, mac, own_mac, dst_mac, count, status):
        """Alert: an ARP/cache entry directly claims the router's own IP
        with a MAC that isn't the router's — an identity announcement.
        """
        label = _STATUS_LABELS[status]
        target = f", targeting {dst_mac}" if dst_mac else ""
        print(
            f"[ALERT][GATEWAY SPOOF][{label}] {ip} (this router's own IP) is "
            f"being claimed by {mac} on {interface}, expected {own_mac} "
            f"({count} detections{target})"
        )

    def _alert_gateway_relay(self, interface, ip, mac, own_mac, proto, count, status):
        """Alert: genuine router-originated traffic (proto is TCP/UDP,
        never forged since the router itself sent it) is physically
        arriving via a MAC that isn't the router's — direct proof of
        active interception, not just an identity claim.
        """
        label = _STATUS_LABELS[status]
        print(
            f"[ALERT][GATEWAY RELAY][{label}] genuine {proto} traffic from this "
            f"router's own IP ({ip}) on {interface} is arriving via {mac} instead "
            f"of {own_mac} — traffic is already being relayed through an attacker "
            f"({count} detections)"
        )

    def _alert_gateway_misdirect(self, interface, victim_mac, wrong_mac, own_mac, count, status):
        """Alert: traffic meant for the router's own IP physically arrived
        at the wrong MAC — evidence from the victim's side that its ARP
        cache is poisoned, complementing the attacker-side evidence above.
        """
        label = _STATUS_LABELS[status]
        print(
            f"[ALERT][GATEWAY SPOOF][{label}] traffic from {victim_mac} addressed to "
            f"this router's IP on {interface} was sent to {wrong_mac} instead of "
            f"{own_mac} — {victim_mac}'s ARP cache appears poisoned ({count} detections)"
        )

    def _alert_binding_spoof(self, interface, ip, mac, known_mac, count, status, dst_mac):

        """Alert: an IP with an already-trusted MAC is now being claimed
        by a different one.
        """
        label = _STATUS_LABELS[status]
        target = f", targeting {dst_mac}" if dst_mac else ""
        print(
            f"[ALERT][{label}] ARP spoof on {interface}: "
            f"{ip} was {known_mac}, now claimed by {mac} "
            f"({count} detections{target})"
        )

    def _alert_router_targeted(self, interface, ip, mac, known_mac, count, status):
        """Alert: a conflicting binding claim was addressed directly and
        specifically to this router's own MAC (unicast, not broadcast or
        incidentally overheard) — meaning the attacker deliberately targeted
        the router's own ARP cache, not just sent a reply that happened to
        be visible on the wire. Distinct from _alert_binding_spoof, which
        covers the same conflict but without evidence of direct targeting.
        """
        label = _STATUS_LABELS[status]
        print(
            f"[ALERT][ROUTER TARGETED][{label}] {ip} was {known_mac}, now directly "
            f"claimed by {mac} to this router's own MAC on {interface} — the "
            f"attacker is specifically targeting this router's ARP cache "
            f"({count} detections)"
        )

    def _alert_router_poisoned(self, interface, victim_ip, wrong_mac, correct_mac, count, status):
        """Alert: this router itself sent traffic meant for a known host to
        the wrong MAC — meaning THIS router's own ARP cache has been
        successfully poisoned regarding that host. The most direct possible
        evidence of a successful attack: it's not a victim's traffic being
        observed, it's the detector's own machine actively misdirecting.
        """
        label = _STATUS_LABELS[status]
        print(
            f"[ALERT][ROUTER POISONED][{label}] this router sent traffic meant for "
            f"{victim_ip} to {wrong_mac} instead of {correct_mac} on {interface} — "
            f"this router's own ARP cache has been compromised ({count} detections)"
        )

    def _alert_host_misdirect(self, interface, victim_ip, sender_mac, wrong_mac, correct_mac, count, status):
        """Alert: traffic addressed to a known, trusted IP arrived at a MAC
        that isn't the one we've bound to that IP — evidence that the
        SENDER's ARP cache has been poisoned regarding that host. Generalizes
        the gateway-misdirect check beyond just the router's own identity.
        """
        label = _STATUS_LABELS[status]
        print(
            f"[ALERT][{label}] traffic from {sender_mac} addressed to {victim_ip} "
            f"on {interface} was sent to {wrong_mac} instead of {correct_mac} — "
            f"{sender_mac}'s ARP cache appears poisoned for {victim_ip}"
        )