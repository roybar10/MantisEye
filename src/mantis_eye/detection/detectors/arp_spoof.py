"""Detects ARP spoofing on the LAN by watching for IP->MAC binding changes.

Scoped to LAN-facing interfaces only, since ARP spoofing is an on-link
attack — it can't be launched from outside the broadcast domain, so
watching WAN would just be noise. LAN interfaces should be passed in via
detect_lan_interfaces() rather than hardcoded, so this holds regardless of
what the bridge/uplink happen to be named, and generalizes past a single
flat LAN to multiple LAN segments (guest network, VLANs, etc.), each
checked independently with interface-scoped keys.

Scope assumption (see README): MantisEye targets a home/small-office
router where the router itself runs DHCP (dnsmasq). The local lease file
is auto-discovered (checked at known default paths) rather than passed
in, so nothing external needs to know dnsmasq's file layout. Enterprise
topologies with a separate DHCP server are out of scope for now — the
correct extension there is sniffing DHCPACK traffic trusting only a
configured server IP, not SSH/API access to a remote DHCP server, which
would add a stored-credential attack surface to the IDS itself.

Trust comes from three tiers, ranked by authority:

1. Own identity — each interface's own (ip, mac), pulled directly from the
   OS at startup and never updated from ANY source. Unconditional ground
   truth; any mismatch is a gateway-impersonation detection.
2. DHCP leases (authoritative) — read from the router's local dnsmasq
   lease file, matched to a tracked interface by subnet membership. CAN
   overwrite an existing passive binding, because it's a fact the router
   generated. Applied before the passive resync each cycle so a genuine
   reassignment is corrected before the passive check would otherwise
   flag it as a mismatch. When a device's IP changes, any other binding
   entry still pointing at that same MAC is removed (a device only holds
   one IP at a time) via a linear scan over `bindings` — acceptable at
   home-router scale (tens of hosts); a mac->key reverse index would make
   this O(1) but was deliberately left out to avoid a second structure
   that needs to stay in sync, until an actual scale need shows up.
3. Passive trust-on-first-use — sniffed ARP replies and periodic `ip
   neigh` resyncs both feed `_observe`, the single shared decision path
   for "is this claim trustworthy." The first MAC seen for an IP is
   trusted permanently and never overwritten by a later conflicting claim
   (only tier 2 can override the trusted value itself).

Suspicion tracking uses a shared three-tier escalation (State pattern,
mirroring PortScanDetector's NEW/STRONG/CONTINUED): SUSPECTED below
confirm_threshold, CONFIRMED at the threshold, ONGOING for every
detection after. Counts decay after idle_expiry of inactivity for that
specific key — this is the ONLY mechanism that reduces suspicion. DHCP
confirming or reassigning an IP never resets it: an unchanged or changed
lease carries no information about whether a past or ongoing attack has
actually stopped.

Tracking keys are anchored to MAC identities, not IP — IP is exactly the
thing that can legitimately change (via DHCP, or a victim's own address
changing) without the attack having stopped, so a counter keyed by IP
would lose continuity across a legitimate reassignment:
- Regular mismatches key on (interface, ip, offending_mac) — the disputed
  IP plus who's disputing it.
- Gateway impersonation keys on (interface, attacker_mac, victim_mac) —
  who is attacking and who they're attacking (event.dst_mac). If the
  victim's own IP changes later, tracked suspicion against that attacker
  survives unaffected, since neither MAC in the key changed.

Detection has two independent input streams, both funneled through the
same _observe pipeline: live sniffed packets (real-time, but can miss
traffic the sniffer's vantage point doesn't see) and periodic re-scans of
the OS's own ARP cache (a safety net that catches the aftermath of a
conflict even if the causing packet itself was missed).
"""

import os
import time
import subprocess
import ipaddress
from scapy.arch import get_if_addr, get_if_hwaddr
from mantis_eye.core.packet_event import PacketEvent

_STATUS_LABELS = {"suspected": "SUSPECTED", "confirmed": "CONFIRMED", "ongoing": "ONGOING"}

_DHCP_LEASE_CANDIDATES = [
    "/var/lib/misc/dnsmasq.leases",  # Debian/Ubuntu default
    "/var/lib/dhcp/dnsmasq.leases",
    "/tmp/dnsmasq.leases",            # OpenWrt / embedded
]


class ArpSpoofDetector:
    """Alerts when an IP with a known MAC suddenly claims a different one,
    or when the router's own IP is impersonated, escalating from suspected
    to confirmed to ongoing as detections accumulate. Learns from sniffed
    ARP replies, periodic OS ARP cache re-scans, and the router's local
    DHCP lease file (auto-discovered).
    """

    def __init__(self, lan_interfaces: list[str], confirm_threshold: int = 3,
                 idle_expiry: int = 300, resync_interval: int = 30):
        """Seeds identity and subnet info per interface, then runs an
        initial resync. `confirm_threshold` is how many detections for the
        same tracking key escalate suspected -> confirmed. `idle_expiry`
        (seconds) resets a key's count if it's gone quiet that long, so a
        stale old conflict can't inflate an unrelated fresh one.
        `resync_interval` (seconds, measured against packet timestamps)
        controls how often DHCP leases and the passive cache get
        re-checked after startup.
        """
        self.lan_interfaces = lan_interfaces
        self.confirm_threshold = confirm_threshold
        self.idle_expiry = idle_expiry
        self.resync_interval = resync_interval
        self._last_resync = 0

        self.own_identity: dict[str, tuple[str, str]] = {}       # interface -> (ip, mac)
        self.bindings: dict[tuple[str, str], str] = {}            # (interface, ip) -> mac
        self.mismatch_state: dict[tuple, dict] = {}                # key -> {"count", "last_seen"}
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
        `bindings` before the passive pass runs — otherwise the passive
        pass would see the same reassignment as an unexplained mismatch.
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
        trusted MAC when it changes. Also removes any other (interface,
        ip) binding currently pointing to the same mac, since a device
        only legitimately holds one IP at a time — otherwise a stale
        entry for an IP the device has since moved on from stays
        "trusted" indefinitely. A linear scan over bindings; fine at
        home-router scale, avoids a second reverse-indexed structure kept
        in sync just for this. Deliberately never touches mismatch_state:
        suspicion only ever fades via idle_expiry, never because DHCP
        reassigned or reconfirmed an IP — that carries no information
        about whether a past or ongoing attack actually stopped.
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
        feeds each entry through `_observe`, exactly like a sniffed reply —
        the second input stream described in the module docstring. Used
        both at startup (cold seed) and periodically while running. Uses
        wall-clock time for the observation timestamp, since a cache entry
        has no packet timestamp of its own — keeps idle_expiry comparisons
        meaningful against later sniffed-packet timestamps. Best-effort
        per interface: a missing or stale cache for one doesn't block
        the others.
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
                        self._observe(iface, ip, mac, dst_mac=None, timestamp=now)

    
   

    def _observe(self, interface: str, ip: str, mac: str, dst_mac, timestamp: float):
        """The single shared trust decision, called from both input
        streams: sniffed ARP replies (via __call__) and OS ARP cache
        re-scans (via _resync_from_neigh_cache). Checks the gateway
        identity first, then falls through to trust-on-first-use for
        everyone else. Never overwrites an existing binding — only
        `_apply_authoritative` can do that. `dst_mac` is `None` for
        cache-derived observations, where "who was this addressed to"
        doesn't apply.
        """
        own_ip, own_mac = self.own_identity[interface]

        if ip == own_ip:
            if mac != own_mac:
                key = (interface, mac, dst_mac or "unknown")
                count = self._track_count(key, timestamp, self.mismatch_state, self.confirm_threshold)
                status = self._status_for(count, self.confirm_threshold)
                self._alert_gateway_spoof(interface, ip, mac, own_mac, dst_mac, count, status)
            return

        key = (interface, ip)
        known_mac = self.bindings.get(key)

        if known_mac is None:
            pkey = (interface, ip, mac)
            count = self._track_count(pkey, timestamp, self.pending_state, self.learn_threshold)
            if count >= self.learn_threshold:
                self.bindings[key] = mac
                self.pending_state.pop(pkey, None)
            return

        if known_mac != mac:
            mkey = (interface, ip, mac)
            count = self._track_count(mkey, timestamp, self.mismatch_state, self.confirm_threshold)
            status = self._status_for(count, self.confirm_threshold)
            self._alert_binding_spoof(interface, ip, mac, known_mac, count, status, dst_mac)

    def _track_count(self, key: tuple, timestamp: float, state: dict, threshold: int) -> int:
        """Generic accumulate-with-decay counter, shared by both mismatch
        tracking (earning suspicion) and pending-binding tracking (earning
        trust) — same mechanics, different meaning depending on caller.
        """
        entry = state.get(key)
        if entry is None or timestamp - entry["last_seen"] > self.idle_expiry:
            count = 1
        else:
            count = entry["count"] + 1
        state[key] = {"count": count, "last_seen": timestamp}
        return count    

    def _status_for(self, count: int, threshold: int) -> str:
        if count < threshold:
            return "suspected"
        elif count == threshold:
            return "confirmed"
        return "ongoing"
        

    def __call__(self, event: PacketEvent):
        """Feeds a sniffed ARP reply into `_observe` (stream 1), then, if
        enough time has passed since the last one, triggers a periodic
        resync of both DHCP leases and the passive ARP cache (stream 2).
        Only ARP replies (op=2) are trusted to assert a binding — requests
        don't claim "I am this IP" the way a reply does.
        """
        if event.arp_op != 2 or event.interface not in self.own_identity:
            return

        self._observe(event.interface, event.src_ip, event.src_mac,
                       event.dst_mac, event.timestamp)

        if event.timestamp - self._last_resync > self.resync_interval:
            self._resync_all()
            self._last_resync = event.timestamp

    def _alert_gateway_spoof(self, interface, ip, mac, own_mac, dst_mac, count, status):
        """Prints a gateway-impersonation alert at the given escalation
        status: someone is claiming this interface's own IP with a MAC
        that isn't the router's.
        """
        label = _STATUS_LABELS[status]
        target = f", targeting {dst_mac}" if dst_mac else ""
        print(
            f"[ALERT][GATEWAY SPOOF][{label}] {ip} (this router's own IP) is "
            f"being claimed by {mac} on {interface}, expected {own_mac} "
            f"({count} detections{target})"
        )

    def _alert_binding_spoof(self, interface, ip, mac, known_mac, count, status, dst_mac):
        """Prints a binding-conflict alert at the given escalation status:
        an IP with an already-trusted MAC is now being claimed by a
        different one.
        """
        label = _STATUS_LABELS[status]
        target = f", targeting {dst_mac}" if dst_mac else ""
        print(
            f"[ALERT][{label}] ARP spoof on {interface}: "
            f"{ip} was {known_mac}, now claimed by {mac} "
            f"({count} detections{target})"
        )