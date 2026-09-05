import time
from collections import defaultdict
from mantis_eye.capture.events import PacketEvent

class PortScanDetector:
    def __init__(self, threshold=5, idle_expiry=300, cleanup_interval=60):
        self.threshold = threshold
        self.idle_expiry = idle_expiry
        self.cleanup_interval = cleanup_interval
        self._last_cleanup = 0
        self.probes = defaultdict(self._new_signal)
        self.confirms = defaultdict(self._new_signal)
        self.incidents = {}  # (interface, attacker, target) -> incident state

    def _new_signal(self):
        return {"ports": set(), "first_seen": None, "last_seen": None, "last_alert_count": 0}

    def __call__(self, event: PacketEvent):
        
        #if event.proto == "tcp":
        #    print(f"[DEBUG] TCP event: {event.src_ip}:{event.port} flags={event.tcp_flags}")
   
        
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
        stale = [k for k, e in state_dict.items()
                 if e["last_seen"] and now - e["last_seen"] > self.idle_expiry]
        for k in stale:
            del state_dict[k]
            self.incidents.pop(k, None)

    def _track(self, state_dict, event, src, dst, role):
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