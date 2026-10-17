"""Detector: shared base for detectors that track Attack objects."""

from mantis_eye.detection.attacks import Attack

class Detector:
    """Base for detectors that track one Attack per
    (interface, attacker_mac, victim_mac) in self.incidents. Gives every
    detector the same way to hand its attacks to the grouping code, so the
    Ctrl+C summary and later the API never need to know which detector
    they are talking to."""

    def __init__(self, name):
        """name is the detector's display name ("ARP", "Port scan"), used as
        the alert prefix, e.g. "[CONFIRMED] ARP attack: ..."."""
        self.name = name
        self.incidents = {}   # (interface, attacker_mac, victim_mac) -> Attack

    def attacks(self):
        """Snapshot of every tracked attack. A copy of the values, so a reader
        never iterates the live dict while packets are still adding
        incidents."""
        return list(self.incidents.values())

    def _alert(self, attack, trigger, **fields):
        """Print one alert line with the layout every detector shares: status
        label, endpoints, count, trigger, latest detail and claimed IPs.
        Detector-specific fields arrive as keyword arguments and are appended
        in the order given, so each detector adds only what is relevant to it."""
        label = Attack._STATUS_LABELS[attack.status]
        parts = [f"count={attack.count}",
                 f"triggered by {trigger}",
                 f"detail={attack.last_detail or ''}",
                 f"claimed_ips={sorted(attack.claimed_ips)}"]
        parts += [f"{key}={value}" for key, value in fields.items()]
        print(f"[{label}] {self.name} attack: {attack.attacker_mac} -> "
              f"{attack.victim_mac} on {attack.interface} ({', '.join(parts)})")

    def _alert_decayed(self, attack):
        """Print the [DECAYED] line for an attack that went idle. Shared so
        every detector words it the same way, using its own display name."""
        print(f"[DECAYED] {self.name} attack: {attack.attacker_mac} -> "
              f"{attack.victim_mac} on {attack.interface} (count={attack.count})")

    def _expire_idle(self, now):
        """Decay every attack idle past its idle_expiry and print a [DECAYED]
        line for each. The status guard matters because is_expired stays true
        for an already-decayed attack, so without it every sweep would decay
        it again and re-print the same line. Count is a lifetime tally and is
        never touched."""
        for attack in self.incidents.values():
            if attack.is_expired(now) and attack.status != Attack.DECAYED:
                attack.decay()
                self._alert_decayed(attack)