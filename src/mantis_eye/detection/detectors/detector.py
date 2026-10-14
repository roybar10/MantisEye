"""Detector: shared base for detectors that track Attack objects."""

class Detector:
    """Base for detectors that track one Attack per
    (interface, attacker_mac, victim_mac) in self.incidents. Gives every
    detector the same way to hand its attacks to the grouping code, so the
    Ctrl+C summary and later the API never need to know which detector
    they are talking to."""

    def __init__(self):
        self.incidents = {}   # (interface, attacker_mac, victim_mac) -> Attack

    def attacks(self):
        """Snapshot of every tracked attack. A copy of the values, so a reader
        never iterates the live dict while packets are still adding
        incidents."""
        return list(self.incidents.values())