"""Port scan detection via independent probe/confirm signal correlation.

Two signals are tracked separately per (interface, src, dst):
  - "probe": SYN bursts from the scanner's perspective.
  - "confirm": RST/RST-ACK bursts from the target's perspective.

RST is treated as a corroborating signal, not noise — a target's RST is harder
to spoof than a SYN flood and independently confirms a scan actually reached a
real host. An incident only escalates from suspected to confirmed once BOTH
signals independently cross the threshold."""

import time
from collections import defaultdict
from mantis_eye.capture.events import PacketEvent

class PortScanDetector:
    """Detects port scans by correlating SYN probes with RST confirmations.

    Incident lifecycle: NEW (one signal crosses threshold) -> STRONG (both
    signals cross threshold independently) -> CONTINUED (further crosses,
    referencing the original start time)."""
    
    def __init__(self, threshold=5, idle_expiry=300, cleanup_interval=60):
        """
        Args:
            threshold: Distinct ports touched before a signal counts as a burst,
                and the increment required before re-alerting on the same key.
            idle_expiry: Seconds of inactivity before a tracked key is forgotten.
                State expiry is built in from day one rather than bolted on later,
                since an unbounded dict is a slow memory leak in a long-running sniffer.
            cleanup_interval: Minimum seconds between expiry sweeps. Time-gated
                (not per-packet) so cleanup cost doesn't scale with packet rate."""
        self.threshold = threshold
        self.idle_expiry = idle_expiry
        self.cleanup_interval = cleanup_interval
        self._last_cleanup = 0
        self.probes = defaultdict(self._new_signal)
        self.confirms = defaultdict(self._new_signal)
        self.incidents = {}  # (interface, attacker, target) -> incident state

    def _new_signal(self):
        """Default state for a freshly-seen (interface, src, dst) key."""
        return {"ports": set(), "first_seen": None, "last_seen": None, "last_alert_count": 0}

    def __call__(self, event: PacketEvent):
        """Entry point invoked by Dispatcher for every tcp PacketEvent.
        Routes SYN packets to the probe signal and RST/RST-ACK packets to the
        confirm signal, then runs a time-gated expiry sweep."""
        
        if event.port is None or event.proto != "tcp":
            return

        if event.tcp_flags == "S":
            self._track(self.probes, event, event.src_ip, event.dst_ip, "probe")

        elif event.tcp_flags in ("R", "RA"):
            self._track(self.confirms, event, event.src_ip, event.dst_ip, "confirm")

        if event.timestamp - self._last_cleanup > self.cleanup_interval:
            self._expire_idle(self.probes, event.timestamp)
            self._expire_idle(self.confirms, event.timestamp)
            self._last_cleanup = event.timestamp

    def _expire_idle(self, state_dict, now):
        """Drop keys that have been idle longer than idle_expiry, and any
        associated incident, so state doesn't grow unbounded over a long capture."""

        stale = [k for k, e in state_dict.items()
                 if e["last_seen"] and now - e["last_seen"] > self.idle_expiry]
        for k in stale:
            del state_dict[k]
            self.incidents.pop(k, None)

    def _track(self, state_dict, event, src, dst, role):
        """Update port-set state for one signal (probe or confirm) and alert
        if the distinct-port count crosses the next threshold multiple.
        Keys on (interface, src, dst) rather than just src_ip, since NAT can
        make the same real host look like different identities across
        interfaces — interface scoping avoids splitting/merging identity incorrectly."""

        key = (event.interface, src, dst)
        entry = state_dict[key]
        if entry["first_seen"] is None:
            entry["first_seen"] = event.timestamp

        entry["last_seen"] = event.timestamp
        entry["ports"].add(event.port)
        count = len(entry["ports"])

        if count >= self.threshold and count >= entry["last_alert_count"] + self.threshold:
            entry["last_alert_count"] = count
            self._update_incident(event, src, dst, role, count)

    def _update_incident(self, event, src, dst, role, port_count):
        """Escalate or continue an incident based on whether the opposing
        signal (probe<->confirm) has also independently crossed threshold.
        For a confirm event, inc_key and other_key both resolve to
        (interface, dst, src) — the confirm's dst/src is already in
        attacker/victim order, unlike probe's src/dst."""
        # incident key: attacker = the one sending SYNs, target = the one sending RSTs
        
        if role == "probe":
            inc_key = (event.interface, src, dst)
            other_key = (event.interface, dst, src)  # confirms use reversed direction
            other_state = self.confirms

        else:
            inc_key = (event.interface, dst, src)
            other_key = (event.interface, dst, src)
            other_state = self.probes

        incident = self.incidents.get(inc_key)
        other_entry = other_state.get(other_key)
        other_confirmed = other_entry and other_entry["last_alert_count"] > 0

        if incident is None:
            self.incidents[inc_key] = {"status": "suspected", "started": event.timestamp}
            print(f"[ALERT][NEW] Port scan suspected: {inc_key[1]} -> {inc_key[2]} "
                f"on {event.interface} ({port_count} ports, role={role})")

        else:
            if other_confirmed and incident["status"] != "confirmed":
                incident["status"] = "confirmed"
                print(f"[ALERT][STRONG] Port scan confirmed: {inc_key[1]} -> {inc_key[2]} "
                    f"on {event.interface}, ongoing since {incident['started']:.0f}")

            else:
                print(f"[ALERT][CONTINUED] Port scan ongoing: {inc_key[1]} -> {inc_key[2]} "
                    f"on {event.interface} ({port_count} ports, role={role}, "
                    f"since {incident['started']:.0f})")