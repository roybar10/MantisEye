"""Domain model for a tracked port-scan incident: two independently-crossed
signals (SYN probe, RST/RST-ACK confirm) correlated into one escalating
incident per (interface, attacker, target), mirroring the same base
Attack lifecycle ArpSpoofAttack uses.
"""

from mantis_eye.detection.attacks.attack import Attack


class PortScanAttack(Attack):
    """One tracked port-scan incident per (interface, attacker, victim).

    Holds the counters the detector uses to decide escalation: SYNs seen
    (probe_packet_count), replies seen (confirm_packet_count), replies that
    answered no known SYN (unmatched_confirm_count), and the set of
    distinct ports touched. The detector reads these and passes the
    resulting min_status to record(); this class never decides status.

    confirm_threshold is set to infinity so the base class's count-based
    escalation can never fire independently of the detector.

    Known limitation: _open_probes entries for SYNs that never get a reply
    (filtered ports) are never removed, so memory grows over a long
    capture.
    """

    KIND = "port_scan"

    def __init__(self, interface, attacker_mac, victim_mac, timestamp, idle_expiry, threshold):
        super().__init__(interface, attacker_mac, victim_mac, timestamp, idle_expiry,
                          confirm_threshold=float("inf"))
        self.threshold = threshold
        self.probe_packet_count = 0
        self.confirm_packet_count = 0
        self.unmatched_confirm_count = 0
        self.scanned_ports = set()
        self.victim_ips = set()
        self.claimed_ips = set()
        self._open_probes = {}   # (src_ip, src_port, dst_ip, dst_port) -> ack its reply must carry
        
    def update_attack(self, role, event):
        """Update this attack's counters and matching state for one packet.

        A SYN ("probe") is stored in _open_probes under its exact connection
        tuple, with the ack number a genuine reply must carry (seq + 1). Any
        reply ("confirm": RST, RST-ACK or SYN-ACK, whatever the port's state)
        clears the matching entry by reversing the tuple and comparing ack
        numbers, and adds no new evidence, since the SYN was already counted.
        A reply that matches nothing is counted as unmatched, independent
        evidence the SYN side missed. Matching on the exact connection rather
        than the port alone means an unrelated reply can never cancel a real
        probe. scanned_ports is a set, so repeat hits on a port don't inflate
        the distinct-port count the sweep alert depends on.

        This method only updates state; it never decides status.

        Args:
            role: "probe" for a SYN, "confirm" for any reply to one.
            event: The PacketEvent for this packet; needs port, src/dst ip and
                port, seq and ack.
        """
        self.scanned_ports.add(event.port)

        if role == "probe":
            self.probe_packet_count += 1
            self.claimed_ips.add(event.src_ip)       # a SYN travels attacker -> victim
            self.victim_ips.add(event.dst_ip)
            key = (event.src_ip, event.src_port, event.dst_ip, event.dst_port)
            self._open_probes[key] = event.seq + 1            # RULE 1

        elif role == "confirm":
            self.confirm_packet_count += 1
            self.claimed_ips.add(event.dst_ip)       # a reply travels victim -> attacker
            self.victim_ips.add(event.src_ip)
            key = (event.dst_ip, event.dst_port, event.src_ip, event.src_port)   # RULE 2a
            if self._open_probes.get(key) == event.ack:       # RULE 2b
                del self._open_probes[key]
            else:
                self.unmatched_confirm_count += 1             # RULE 3

    def record(self, role, timestamp, scanned_ports=None,detail=None, min_status=None):
        """Pass-through to Attack.record, kept so callers use one entry point
        per attack type. State updates happen in update_attack beforehand."""
        super().record(role, timestamp, detail, min_status)

    def _details(self):
        return {
            "ports": sorted(self.scanned_ports),
            "victim_ips": sorted(self.victim_ips),
            "probes": self.probe_packet_count,
            "replies": self.confirm_packet_count,
            "unmatched_replies": self.unmatched_confirm_count,
        }