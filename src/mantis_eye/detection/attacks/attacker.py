"""Attacker: the attacking host behind one or more attacks, identified by
(interface, MAC). Built on demand by Attacker.group from any detectors' Attack objects. IPs are only ever claims made in packets, so they are
summarized from the attacks and never used as the Attacker's identity.
"""

from mantis_eye.detection.attacks.attack import Attack

class Attacker:
    """One attacking host, identified by (interface, MAC), the only identity
    observed directly. IPs are claims made in packets, so they are summarized
    from the attacks and never used for identity. Holds references to the
    detectors' Attack objects, not copies, so there is no second copy to keep
    in sync."""

    def __init__(self, interface, mac):
        self.interface = interface
        self.mac = mac
        self.attacks = []

    @property
    def claimed_ips(self):
        """Every IP this MAC has claimed across all of its attacks."""
        return set().union(*(a.claimed_ips for a in self.attacks))

    @classmethod
    def group(cls, attacks):
        """Group attacks into one Attacker per (interface, attacker_mac). Takes
        plain Attack objects, so it works for any detector without knowing
        their types."""
        attackers = {}
        for attack in attacks:
            key = (attack.interface, attack.attacker_mac)
            attackers.setdefault(key, cls(*key)).attacks.append(attack)
        return list(attackers.values())

    @staticmethod
    def summarize(attackers):
        """Console text for a list of attackers: a header, then each attacker's
        own description. Returns the text instead of printing it, so the caller
        decides where it goes."""
        if not attackers:
            return "\nNo attackers detected."
        blocks = [f"\n=== {len(attackers)} attacker(s) ==="]
        blocks += [a.describe_attacker() for a in attackers]
        return "\n".join(blocks)

    def describe_attacker(self):
        """Text block for console output: the attacker's MAC and claimed IPs,
        then one line per attack. Returns the text instead of printing it, so
        the caller decides where it goes (console now, something else later)."""
        lines = [f"{self.mac} on {self.interface}, claimed_ips={sorted(self.claimed_ips)}"]
        for a in self.attacks:
            label = Attack._STATUS_LABELS[a.status]
            lines.append(f"  [{label}] {type(a).__name__} -> {a.victim_mac} (count={a.count})")
        return "\n".join(lines)