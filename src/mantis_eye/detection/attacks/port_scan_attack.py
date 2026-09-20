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

    def __init__(self, interface, attacker_mac, victim_mac, timestamp, idle_expiry):
        super().__init__(interface, attacker_mac, victim_mac, timestamp, idle_expiry,
                          confirm_threshold=float("inf"))
        self.probe_crossed = False
        self.confirm_crossed = False

    def record(self, check_name, timestamp, detail=None, min_status=None):
        """check_name is "probe" or "confirm" here. min_status is only
        asserted once both signals have independently crossed at least
        once — a single signal alone, however many times it re-crosses,
        never floors status on its own.
        """
        if check_name == "probe":
            self.probe_crossed = True
        else:
            self.confirm_crossed = True

        min_status = "confirmed" if (self.probe_crossed and self.confirm_crossed) else None
        super().record(check_name, timestamp, detail, min_status)