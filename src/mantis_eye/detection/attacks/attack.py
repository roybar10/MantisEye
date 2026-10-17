"""Base class for a tracked attack/incident. Owns evidence accumulation,
decay, and status escalation mechanics; subclasses define their own
identity fields and status vocabulary.
"""

class Attack:
    """Base class for a tracked incident. Owns evidence accumulation, decay
    and status escalation; subclasses add identity fields.

    Status is floor-driven: each detector decides when its evidence is
    strong enough and passes min_status to record(). The base class never
    reasons about counts, except for one built-in step, confirmed ->
    ongoing, on any further evidence. "decayed" sits outside the severity
    ladder (_STATUS_ORDER) because it describes inactivity, not severity.
    """
    _STATUS_ORDER = ("suspected", "confirmed", "ongoing")
    DECAYED = "decayed"
    KIND = "generic"
    _STATUS_LABELS = {"suspected": "SUSPECTED", "confirmed": "CONFIRMED", "ongoing": "ONGOING", "decayed": "DECAYED"}
    _BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

    def __init__(self, interface, attacker_mac, victim_mac,timestamp, idle_expiry, confirm_threshold):
        """Create a new attack instance, starting at the lowest status with
        zero accumulated evidence. idle_expiry and confirm_threshold are
        stored per-instance (rather than looked up from the detector) so an
        Attack is self-contained and testable without a detector present.
        """
        self.interface = interface
        self.attacker_mac = attacker_mac
        self.victim_mac = victim_mac
        self.claimed_ips = set()   # IPs this attack claims; claims, never trusted identity
        self.status = self._STATUS_ORDER[0]
        self._pre_decay_status = None
        self.count = 0
        self.first_seen = timestamp
        self.last_seen = timestamp
        self.evidence = []  # [(check_name, timestamp, detail)]
        self.idle_expiry = idle_expiry
        self.confirm_threshold = confirm_threshold

    def record(self, role, timestamp, detail=None, min_status=None):
        """Log one piece of evidence and re-derive status.
        count is a lifetime tally and never decreases, since decay affects
        current status, not the memory of what happened. min_status lets the
        caller assert a floor when its evidence is strong enough on its own;
        see _escalate for how the floor is combined with the current status.
        """
        self.count += 1
        self.last_seen = timestamp
        self.evidence.append((role, timestamp, detail))
        self._escalate(min_status)

    def _escalate(self, min_status):
        """Pick the new status as the highest of: the current status, the
        caller's floor, and the built-in confirmed -> ongoing step.
        A decayed attack is first restored to the status it held before
        decaying (_pre_decay_status), so renewed evidence snaps it back to its
        prior peak rather than re-climbing from "suspected". Escalation is
        otherwise driven only by min_status; nothing here counts evidence.
        """
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
        """True if no evidence has arrived within idle_expiry of now. Callers
        use it to decay idle attacks. An attack that has already decayed stays
        expired until new evidence arrives, so callers must check status
        before announcing a decay again."""
        return now - self.last_seen > self.idle_expiry

    def to_dict(self):
        """Plain-dict snapshot of the fields every attack shares, plus the
        type-specific ones from _details(). Sets become sorted lists, so the
        result can go straight to JSON (API) or a database column."""
        return {
            "kind": self.KIND,
            "interface": self.interface,
            "attacker_mac": self.attacker_mac,
            "victim_mac": self.victim_mac,
            "status": self.status,
            "count": self.count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "claimed_ips": sorted(self.claimed_ips),
            "checks": sorted({role for role, _, _ in self.evidence}),
            "details": self._details(),
        }

    def _details(self):
        """Type-specific fields for to_dict(); subclasses override."""
        return {}