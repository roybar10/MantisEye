"""ArpSpoofAttack — one tracked ARP-spoof/MITM incident, identified by
(interface, attacker_mac, victim_mac). All five ArpSpoofDetector checks
that implicate the same attacker/victim pair record into the same
instance, so evidence from different detection paths (an ARP announcement,
later corroborated by a TCP relay, etc.) accumulates into one incident
instead of fragmenting across unrelated counters.
"""

from mantis_eye.detection.attacks.attack import Attack


class ArpSpoofAttack(Attack):
    def __init__(self, interface, attacker_mac, victim_mac, timestamp, idle_expiry, confirm_threshold):
        """Extend Attack with the ARP-specific identity pair (attacker_mac,
        victim_mac) and a set of every IP the attacker has claimed during
        this incident, useful for reporting the full scope of an attack
        even if the attacker rotated through multiple IPs.
        """
        super().__init__(interface, attacker_mac, victim_mac, timestamp, idle_expiry, confirm_threshold)
        self.claimed_ips = set()

    def record(self, check_name, timestamp, detail=None, claimed_ip=None, min_status=None):
        """Same as Attack.record, plus tracking claimed_ip (when the
        triggering evidence involved the attacker claiming a specific IP)
        into claimed_ips before delegating the rest to the base class.
        """
        if claimed_ip:
            self.claimed_ips.add(claimed_ip)
        super().record(check_name, timestamp, detail, min_status)