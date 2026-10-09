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
    
    def __init__(self, threshold=5, idle_expiry=300, cleanup_interval=60, port_alert_threshold=5):
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
        self.port_alert_threshold = port_alert_threshold
        self._last_cleanup = 0
        self.incidents = {}  # (interface, attacker, target) -> PortScanAttack

    def __call__(self, event: PacketEvent):
        """Entry point invoked by Dispatcher for every tcp PacketEvent.
        Routes SYN packets to the probe signal and RST/RST-ACK packets to the
        confirm signal, then runs a time-gated expiry sweep."""

        if event.timestamp - self._last_cleanup > self.cleanup_interval:
            self._expire_idle(event.timestamp)
            self._last_cleanup = event.timestamp
        
        if event.port is None or event.proto != "tcp":
            return

        if event.tcp_flags == "S":
            self._observe(event, event.src_ip, event.dst_ip, "probe")

        elif event.tcp_flags in ("R", "RA"):
            self._observe(event, event.src_ip, event.dst_ip, "confirm")

       
    def _observe(self, event, src, dst, role):
        """Update port-set state for one signal (probe or confirm) and alert
        if the distinct-port count crosses the next threshold multiple.
        Keys on (interface, src, dst) rather than just src_ip, since NAT can
        make the same real host look like different identities across
        interfaces — interface scoping avoids splitting/merging identity incorrectly."""

        attacker_mac, victim_mac = (src, dst) if role == "probe" else (dst, src)
        attack = self._get_attack(event.interface, attacker_mac, victim_mac, event.timestamp)
        
        port_count_before = len(attack.scanned_ports)
        attack.update_attack(role, event)
        port_count_after = len(attack.scanned_ports)

        if port_count_after != port_count_before and port_count_after != 0 and port_count_after % self.port_alert_threshold == 0:
            self._alert_new_ports(attack, port_count_after)

        crossed = (attack.probe_packet_count >= self.threshold
           or attack.confirm_packet_count >= self.threshold
           or attack.probe_packet_count + attack.unmatched_confirm_count >= self.threshold)

        attack.record(role, event.timestamp,
                    detail=f"{role} packet, {len(attack.scanned_ports)} distinct ports",
                    min_status="confirmed" if crossed else None)

        self._alert(attack, role)

    def _get_attack(self, interface, attacker_mac, victim_mac, timestamp):
        key = (interface, attacker_mac, victim_mac)
        attack = self.incidents.get(key)
        if attack is None:
            attack = PortScanAttack(interface, attacker_mac, victim_mac, timestamp, self.idle_expiry, self.threshold)
            self.incidents[key] = attack
        return attack

    def _alert(self, attack, role):
        label = Attack._STATUS_LABELS[attack.status]
        print(f"[{label}] Port scan attack: {attack.attacker_mac} -> {attack.victim_mac} "
            f"on {attack.interface} (count={attack.count}, triggered by {role}, "
            f"probes={attack.probe_packet_count}, confirms={attack.confirm_packet_count}, "
            f"unmatched={attack.unmatched_confirm_count}, "
            f"ports={sorted(attack.scanned_ports)})")

    def _alert_new_ports(self, attack, port_count):
        print(f"[PORT SWEEP] {attack.attacker_mac} -> {attack.victim_mac} on {attack.interface} "
            f"has now touched {port_count} distinct ports")

    def _expire_idle(self, now):
        """Decay incidents idle past idle_expiry and print a [DECAYED] line for
        each one. The status guard matters because is_expired stays true for an
        already-decayed incident, so without it every sweep would decay it again
        and re-print the same line. Count is a lifetime tally and is never touched."""
        for attack in self.incidents.values():
            if attack.is_expired(now) and attack.status != Attack.DECAYED:
                attack.decay()
                print(f"[DECAYED] Port scan attack: {attack.attacker_mac} -> "
                    f"{attack.victim_mac} on {attack.interface} (count={attack.count})")

