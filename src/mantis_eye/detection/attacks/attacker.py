"""Attacker: the attacking host behind one or more attacks, identified by
(interface, MAC). Built on demand by group_by_attacker from any detector's
Attack objects. IPs are only ever claims made in packets, so they are
summarized from the attacks and never used as the Attacker's identity.
"""

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


def group_by_attacker(attacks):
    """Group attacks into one Attacker per (interface, attacker_mac). Takes
    plain Attack objects, so it works for any detector without knowing
    their types."""
    attackers = {}
    for attack in attacks:
        key = (attack.interface, attack.attacker_mac)
        attackers.setdefault(key, Attacker(*key)).attacks.append(attack)
    return list(attackers.values())