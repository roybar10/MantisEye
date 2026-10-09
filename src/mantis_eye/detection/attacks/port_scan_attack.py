"""Domain model for a tracked port-scan incident: two independently-crossed
signals (SYN probe, RST/RST-ACK confirm) correlated into one escalating
incident per (interface, attacker, target), mirroring the same base
Attack lifecycle ArpSpoofAttack uses.
"""

from mantis_eye.detection.attacks.attack import Attack


class PortScanAttack(Attack):
    """Extend Attack with the port-scan-specific identity pair (attacker_mac,
    victim_mac) and two independent signal flags (probe_crossed,
    confirm_crossed).

    Overrides confirm_threshold to an unreachable value so Attack's base
    count-based escalation never fires on its own — count only measures
    "how many times either signal re-crossed," which says nothing about
    whether the *other* signal ever corroborated it. Escalation to
    "confirmed" only happens via the explicit min_status floor passed in
    record() once both signals have independently crossed at least once;
    from there, Attack's existing "any further evidence advances one
    step" rule (identical to ArpSpoofAttack) takes over for
    confirmed->ongoing.
    """

    def __init__(self, interface, attacker_mac, victim_mac, timestamp, idle_expiry, threshold):
        super().__init__(interface, attacker_mac, victim_mac, timestamp, idle_expiry,
                          confirm_threshold=float("inf"))
        self.threshold = threshold
        self.probe_packet_count = 0
        self.confirm_packet_count = 0
        self.unmatched_confirm_count = 0
        self.scanned_ports = set()
        self._open_probes = {}   # (src_ip, src_port, dst_ip, dst_port) -> ack its reply must carry
        
    def update_attack(self, role, event):
        """Update this attack's counters and matching state for one packet.

        A SYN ("probe") is stored in _open_probes under its exact connection
        tuple, with the ack number a genuine reply must carry (seq + 1). An RST
        ("confirm") is matched by reversing that tuple and comparing ack
        numbers: a match is the target answering a SYN we already counted, so it
        adds no new evidence, while anything else is counted as unmatched, which
        is independent evidence the SYN side missed. Matching on the exact
        connection rather than the port alone means an unrelated RST can never
        cancel a real probe. scanned_ports is a set, so repeat hits on a port
        don't inflate the distinct-port count the sweep alert depends on.

        This method only updates state; it never decides status. The detector
        reads the counters afterwards and passes min_status to record().

        Args:
            role: "probe" for a SYN, "confirm" for an RST/RST-ACK.
            event: The PacketEvent for this packet; needs port, src/dst ip and
                port, seq and ack.
        """
        self.scanned_ports.add(event.port)

        if role == "probe":
            self.probe_packet_count += 1
            key = (event.src_ip, event.src_port, event.dst_ip, event.dst_port)
            self._open_probes[key] = event.seq + 1            # RULE 1

        elif role == "confirm":
            self.confirm_packet_count += 1
            key = (event.dst_ip, event.dst_port, event.src_ip, event.src_port)   # RULE 2a
            if self._open_probes.get(key) == event.ack:       # RULE 2b
                del self._open_probes[key]
            else:
                self.unmatched_confirm_count += 1             # RULE 3
    
    def record(self, role, timestamp, scanned_ports=None,detail=None, min_status=None):
        super().record(role, timestamp, detail, min_status)