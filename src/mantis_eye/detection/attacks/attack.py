"""Base class for a tracked attack/incident. Owns evidence accumulation,
decay, and status escalation mechanics; subclasses define their own
identity fields and status vocabulary.
"""

class Attack:

    _STATUS_ORDER = ("suspected", "confirmed", "ongoing")
    DECAYED = "decayed"
    _STATUS_LABELS = {"suspected": "SUSPECTED", "confirmed": "CONFIRMED", "ongoing": "ONGOING", "decayed": "DECAYED"}
    _BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
   "decayed": "DECAYED"

    def __init__(self, interface, attacker_mac, victim_mac,timestamp, idle_expiry, confirm_threshold):
        """Create a new attack instance, starting at the lowest status with
        zero accumulated evidence. idle_expiry and confirm_threshold are
        stored per-instance (rather than looked up from the detector) so an
        Attack is self-contained and testable without a detector present.
        """
        self.interface = interface
        self.attacker_mac = attacker_mac
        self.victim_mac = victim_mac
        self.status = self._STATUS_ORDER[0]
        self._pre_decay_status = None
        self.count = 0
        self.first_seen = timestamp
        self.last_seen = timestamp
        self.evidence = []  # [(check_name, timestamp, detail)]
        self.idle_expiry = idle_expiry
        self.confirm_threshold = confirm_threshold

    def record(self, role, timestamp, detail=None, min_status=None):
        """Log one piece of evidence against this attack and re-derive its
        status. A gap since the last evidence longer than idle_expiry resets
        the count — the attack has "cooled off" and needs to re-accumulate
        suspicion — but identity and evidence history are kept regardless,
        since decay affects current suspicion, not memory of what happened.
        min_status lets the calling check assert a floor on severity when
        its evidence is direct proof rather than a mere claim; see
        _escalate for how it's combined with the count-derived status.
        """
        self.count += 1
        self.last_seen = timestamp
        self.evidence.append((role, timestamp, detail))
        self._escalate(min_status)


    def _escalate(self, min_status):
        order = self._STATUS_ORDER
        current = self._pre_decay_status if self.status == self.DECAYED else self.status

        if current == "confirmed":
            current = "ongoing"

        candidates = [current] + ([min_status] if min_status else [])
        self.status = max(candidates, key=order.index)
        self._pre_decay_status = None

    def decay(self):
        """Mark as decayed due to inactivity, remembering the status held
        beforehand so a later record() resumes escalation from there rather
        than starting over from "suspected"."""
        if self.status != self.DECAYED:
            self._pre_decay_status = self.status
            self.status = self.DECAYED
            
    def is_expired(self, now):
        """True if no evidence has been recorded within idle_expiry of now —
        used by callers to prune long-idle attacks from tracking state."""
        return now - self.last_seen > self.idle_expiry