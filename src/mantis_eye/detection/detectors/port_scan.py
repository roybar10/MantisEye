"""Port scan detection via independent probe/confirm signal correlation.

Two signals are tracked separately per (interface, src, dst):
  - "probe": SYN bursts from the scanner's perspective.
  - "confirm": RST/RST-ACK bursts from the target's perspective.

RST is treated as a corroborating signal, not noise — a target's RST is harder
to spoof than a SYN flood and independently confirms a scan actually reached a
real host. An incident only escalates from suspected to confirmed once BOTH
signals independently cross the threshold."""

import time
from collections import defaultdict

from mantis_eye.core.packet_event import PacketEvent
from mantis_eye.detection.attacks import Attack, PortScanAttack

class PortScanDetector:
    """Detects port scans by correlating SYN probes with RST confirmations.

    Incident lifecycle: NEW (one signal crosses threshold) -> STRONG (both
    signals cross threshold independently) -> CONTINUED (further crosses,
    referencing the original start time)."""
    
    def __init__(self, threshold=5, idle_expiry=300, cleanup_interval=60):
        """
        Args:
            threshold: Distinct ports touched before a signal counts as a burst,
                and the increment required before re-alerting on the same key.
            idle_expiry: Seconds of inactivity before a tracked key is forgotten.
                State expiry is built in from day one rather than bolted on later,
                since an unbounded dict is a slow memory leak in a long-running sniffer.
            cleanup_interval: Minimum seconds between expiry sweeps. Time-gated
                (not per-packet) so cleanup cost doesn't scale with packet rate."""
        self.threshold = threshold
        self.idle_expiry = idle_expiry
        self.cleanup_interval = cleanup_interval
        self._last_cleanup = 0
        self.probes = defaultdict(self._new_signal)
        self.confirms = defaultdict(self._new_signal)
        self.incidents = {}  # (interface, attacker, target) -> incident state
        self._combined_last_alert = {}  # (interface, attacker, victim) -> last combined port-count alerted at

    def _new_signal(self):
        """Default state for a freshly-seen (interface, src, dst) key."""
        return {"ports": set(), "first_seen": None, "last_seen": None, "last_alert_count": 0}

    def __call__(self, event: PacketEvent):
        """Entry point invoked by Dispatcher for every tcp PacketEvent.
        Routes SYN packets to the probe signal and RST/RST-ACK packets to the
        confirm signal, then runs a time-gated expiry sweep."""
        
        if event.port is None or event.proto != "tcp":
            return

        if event.tcp_flags == "S":
            self._observe(self.probes, event, event.src_ip, event.dst_ip, "probe")

        elif event.tcp_flags in ("R", "RA"):
            self._observe(self.confirms, event, event.src_ip, event.dst_ip, "confirm")

        if event.timestamp - self._last_cleanup > self.cleanup_interval:
            self._expire_idle(self.probes, event.timestamp)
            self._expire_idle(self.confirms, event.timestamp, reverse_incident_key=True)
            self._last_cleanup = event.timestamp

    def _observe(self, state_dict, event, src, dst, role):
        """Update port-set state for one signal (probe or confirm) and alert
        if the distinct-port count crosses the next threshold multiple.
        Keys on (interface, src, dst) rather than just src_ip, since NAT can
        make the same real host look like different identities across
        interfaces — interface scoping avoids splitting/merging identity incorrectly."""

        key = (event.interface, src, dst)
        entry = state_dict[key]
        if entry["first_seen"] is None:
            entry["first_seen"] = event.timestamp

        entry["last_seen"] = event.timestamp
        entry["ports"].add(event.port)
        count = len(entry["ports"])
        
        attacker_mac, victim_mac = (src, dst) if role == "probe" else (dst, src)
        probe_entry = self.probes.get((event.interface, attacker_mac, victim_mac))
        confirm_entry = self.confirms.get((event.interface, victim_mac, attacker_mac))
        combined_ports = (probe_entry["ports"] if probe_entry else set()) | \
                      (confirm_entry["ports"] if confirm_entry else set())
        combined_count = len(combined_ports)
        print("combined_ports" + str(combined_ports))
        
        if count >= self.threshold and count >= entry["last_alert_count"] + self.threshold:
            entry["last_alert_count"] = count
            self._update_incident(event, src, dst, role, count)
            return

        ckey = (event.interface, attacker_mac, victim_mac)
        last_combined = self._combined_last_alert.get(ckey, 0)
        if combined_count >= self.threshold and combined_count >= last_combined + self.threshold:
            self._combined_last_alert[ckey] = combined_count
            self._update_incident_combined(event.interface, attacker_mac, victim_mac, event.timestamp, combined_count)

    def _update_incident(self, event, src, dst, role, port_count):
        """role is "probe" or "confirm"; normalizes both into
        (interface, attacker, victim) order — a confirm's dst/src is already
        in attacker/victim order, unlike probe's src/dst.
        """
        if role == "probe":
            attacker_mac, victim_mac = src, dst
        else:
            attacker_mac, victim_mac = dst, src

        attack = self._get_attack(event.interface, attacker_mac, victim_mac, event.timestamp)
        attack.record(role, event.timestamp, detail=f"{role} crossed with {port_count} distinct ports")
        self._alert(attack, role)

    def _update_incident_combined(self, interface, attacker_mac, victim_mac, timestamp, combined_count):
        """Alert when the union of probe+confirm ports (neither alone
        reaching threshold) crosses threshold — covers the case where
        capture missed enough of one direction that neither signal alone
        proves a scan, but together they clearly do."""
        attack = self._get_attack(interface, attacker_mac, victim_mac, timestamp)
        attack.record("combined", timestamp,
                    detail=f"combined probe+confirm reached {combined_count} distinct ports")
        self._alert(attack, "combined")

    def _get_attack(self, interface, attacker_mac, victim_mac, timestamp):
        key = (interface, attacker_mac, victim_mac)
        attack = self.incidents.get(key)
        if attack is None:
            attack = PortScanAttack(interface, attacker_mac, victim_mac, timestamp, self.idle_expiry)
            self.incidents[key] = attack
        return attack

    def _alert(self, attack, role):
        label = Attack._STATUS_LABELS[attack.status]
        print(f"[{label}] Port scan attack: {attack.attacker_mac} -> {attack.victim_mac} "
            f"on {attack.interface} (count={attack.count}, triggered by {role}, "
            f"probe_crossed={attack.probe_crossed}, confirm_crossed={attack.confirm_crossed})")

    def _expire_idle(self, state_dict, now, reverse_incident_key=False):
        """Drop keys that have been idle longer than idle_expiry, and any
        associated incident, so state doesn't grow unbounded over a long capture."""

        stale = [k for k, e in state_dict.items()
                 if e["last_seen"] and now - e["last_seen"] > self.idle_expiry]
        for k in stale:
            del state_dict[k]
            incident_key = (k[0], k[2], k[1]) if reverse_incident_key else k
            self.incidents.pop(k, None)
