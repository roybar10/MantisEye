"""Base class for a tracked attack/incident. Owns evidence accumulation,
decay, and status escalation mechanics; subclasses define their own
identity fields and status vocabulary.
"""

class Attack:
    _STATUS_ORDER = ("suspected", "confirmed", "ongoing")

    def __init__(self, interface, timestamp, idle_expiry, confirm_threshold):
        """Create a new attack instance, starting at the lowest status with
        zero accumulated evidence. idle_expiry and confirm_threshold are
        stored per-instance (rather than looked up from the detector) so an
        Attack is self-contained and testable without a detector present.
        """
        self.interface = interface
        self.status = self._STATUS_ORDER[0]
        self.count = 0
        self.first_seen = timestamp
        self.last_seen = timestamp
        self.evidence = []  # [(check_name, timestamp, detail)]
        self.idle_expiry = idle_expiry
        self.confirm_threshold = confirm_threshold

    def record(self, check_name, timestamp, detail=None, min_status=None):
        """Log one piece of evidence against this attack and re-derive its
        status. A gap since the last evidence longer than idle_expiry resets
        the count — the attack has "cooled off" and needs to re-accumulate
        suspicion — but identity and evidence history are kept regardless,
        since decay affects current suspicion, not memory of what happened.
        min_status lets the calling check assert a floor on severity when
        its evidence is direct proof rather than a mere claim; see
        _escalate for how it's combined with the count-derived status.
        """
        if timestamp - self.last_seen > self.idle_expiry:
            self.count = 0
        self.count += 1
        self.last_seen = timestamp
        self.evidence.append((check_name, timestamp, detail))
        self._escalate(min_status)

    def _escalate(self, min_status):
        """Recompute self.status from three candidate answers: the status
        the raw count alone would justify, the status the attack already
        had, and the optional floor supplied by the calling check
        (min_status). The highest-ranked of the three wins. Including the
        current status as a candidate is what guarantees status never moves
        backward here — the only thing that lowers suspicion is time
        passing without new evidence, handled via idle_expiry in record().
        """
        order = self._STATUS_ORDER
        computed = order[min(self.count, len(order) - 1)] if self.count >= self.confirm_threshold else order[0]
        candidates = [self.status, computed] + ([min_status] if min_status else [])
        self.status = max(candidates, key=order.index)

    def is_expired(self, now):
        """True if no evidence has been recorded within idle_expiry of now —
        used by callers to prune long-idle attacks from tracking state."""
        return now - self.last_seen > self.idle_expiry