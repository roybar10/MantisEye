"""Port scan detection by correlating SYN probes with the replies they draw.

Per (interface, attacker, victim), one PortScanAttack tracks:
  - probes: SYN packets from the scanner.
  - replies: RST, RST-ACK or SYN-ACK from the victim. A reply is matched to
    its SYN by exact connection tuple and ack number; a matched reply adds
    no new evidence, while an unmatched one counts as independent evidence
    (a scan whose SYNs we missed, or backscatter; a human reviews the logs).

An incident becomes confirmed when the SYN count reaches the threshold, the
reply count reaches it, or SYNs plus unmatched replies reach it. Status then
follows the Attack model: suspected -> confirmed -> ongoing, with decayed as
an out-of-band state for idle incidents."""

import time
from collections import defaultdict

from mantis_eye.core.packet_event import PacketEvent
from mantis_eye.detection.attacks import Attack, PortScanAttack
from mantis_eye.detection.detectors.detector import Detector

class PortScanDetector(Detector):
    """Detects port scans by tracking SYN/reply correlation per incident.

    Every packet updates one incident and prints an alert. Alerting on every
    packet is deliberate: it is noisy on busy captures, and re-alert
    throttling is left for later. A separate [PORT SWEEP] line marks each
    time the distinct-port count reaches a multiple of port_alert_threshold,
    and a [DECAYED] line marks an incident going idle."""
    
    def __init__(self, threshold=5, idle_expiry=300, cleanup_interval=60, port_alert_threshold=5):
        """
        Args:
            threshold: Packet count at which an incident is confirmed, checked
                three ways: SYNs alone, replies alone, or SYNs plus unmatched
                replies.
            idle_expiry: Seconds of inactivity before an incident is decayed.
                Decayed incidents are kept, not deleted, so renewed activity
                resumes the same incident at its prior status.
            cleanup_interval: Minimum seconds between decay sweeps. Time-gated
                rather than per-packet so cleanup cost doesn't scale with
                packet rate.
            port_alert_threshold: A [PORT SWEEP] line prints each time the
                incident's distinct-port count reaches a multiple of this.
                Independent of threshold.
        """
        super().__init__("Port scan")
        self.threshold = threshold
        self.idle_expiry = idle_expiry
        self.cleanup_interval = cleanup_interval
        self.port_alert_threshold = port_alert_threshold
        self._last_cleanup = 0

    def __call__(self, event: PacketEvent):
        """Entry point invoked by the Dispatcher for every tcp PacketEvent.

        Runs the time-gated decay sweep first, so a packet resuming a long-idle
        incident finds it already decayed and can restore it, instead of
        refreshing last_seen before the sweep looks. Then routes SYNs to the
        probe signal and RST, RST-ACK and SYN-ACK to the reply ("confirm")
        signal."""

        if event.timestamp - self._last_cleanup > self.cleanup_interval:
            self._expire_idle(event.timestamp)
            self._last_cleanup = event.timestamp
        
        if event.port is None or event.proto != "tcp":
            return

        if event.tcp_flags == "S":
            self._observe(event, event.src_mac, event.dst_mac, "probe")

        elif event.tcp_flags in ("R", "RA", "SA"):
            self._observe(event, event.src_mac, event.dst_mac, "confirm")
    
    def _observe(self, event, src_mac, dst_mac, role):
        """Fold one packet into its incident and alert.

        Keyed on (interface, attacker, victim), scoped by interface because
        NAT can make one real host look like different identities across
        interfaces. Replies swap src and dst so both directions of an exchange
        land on the same incident. Order matters: counters update first, so the
        confirmation check includes this packet. A [PORT SWEEP] line prints
        when the distinct-port count has just reached a multiple of
        port_alert_threshold; the before/after comparison keeps repeat hits on
        already-scanned ports from re-firing it. The confirmation clauses that
        are currently true are passed to the alert as confirmed_by."""

        attacker_mac, victim_mac = (src_mac, dst_mac) if role == "probe" else (dst_mac, src_mac)
        attack = self._get_attack(event.interface, attacker_mac, victim_mac, event.timestamp)
        
        port_count_before = len(attack.scanned_ports)
        attack.update_attack(role, event)
        port_count_after = len(attack.scanned_ports)

        if port_count_after != port_count_before and port_count_after != 0 and port_count_after % self.port_alert_threshold == 0:
            self._alert_new_ports(attack, port_count_after)

        reasons = []
        if attack.probe_packet_count >= self.threshold:
            reasons.append("syns")
        if attack.confirm_packet_count >= self.threshold:
            reasons.append("replies")
        if attack.probe_packet_count + attack.unmatched_confirm_count >= self.threshold:
            reasons.append("syns+unmatched")

        n = port_count_after
        attack.record(role, event.timestamp,
                    detail=f"{role} packet, {n} distinct port{'s' if n != 1 else ''}",
                    min_status="confirmed" if reasons else None)

        self._alert(attack, role, reasons)

    def _get_attack(self, interface, attacker_mac, victim_mac, timestamp):
        """Fetch the incident for this (interface, attacker_mac, victim_mac), creating
        it on first evidence. The single place the key shape is applied."""
        key = (interface, attacker_mac, victim_mac)
        attack = self.incidents.get(key)
        if attack is None:
            attack = PortScanAttack(interface, attacker_mac, victim_mac, timestamp, self.idle_expiry, self.threshold)
            self.incidents[key] = attack
        return attack

    def _alert(self, attack, role, reasons=()):
        """Add the port-scan-specific fields (packet counters, which confirmation
        clauses are true, the distinct ports touched and the victim IPs) and let
        Detector._alert print the shared layout."""
        fields = {"probes": attack.probe_packet_count,
                "confirms": attack.confirm_packet_count,
                "unmatched": attack.unmatched_confirm_count}
        if reasons:
            fields["confirmed_by"] = list(reasons)
        fields["ports"] = sorted(attack.scanned_ports)
        fields["victim_ips"] = sorted(attack.victim_ips)
        super()._alert(attack, role, **fields)
        
    def _alert_new_ports(self, attack, port_count):
        """Print a [PORT SWEEP] line: a one-off marker that the incident has
        just reached another multiple of port_alert_threshold distinct ports,
        separate from the per-packet status alert."""
        print(f"[PORT SWEEP] {attack.attacker_mac} -> {attack.victim_mac} on {attack.interface} "
            f"has now touched {port_count} distinct ports")
