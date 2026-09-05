import time
from collections import defaultdict
from mantis_eye.capture.events import PacketEvent

class PortScanDetector:
    def __init__(self, window_secs=30, threshold=5):
        self.window_secs = window_secs
        self.threshold = threshold
        self.probes = defaultdict(lambda: {"ports": set(), "first_seen": None, "alerted": False})
        self.confirms = defaultdict(lambda: {"ports": set(), "first_seen": None, "alerted": False})

    def __call__(self, event: PacketEvent):
        if event.port is None or event.proto != "tcp":
            return

        if event.tcp_flags == "S":
            self._track(self.probes, event, event.src_ip, event.dst_ip, "probe")
        elif event.tcp_flags in ("R", "RA"):
            self._track(self.confirms, event, event.src_ip, event.dst_ip, "confirm")

    def _track(self, state_dict, event, src, dst, role):
        key = (event.interface, src, dst)
        entry = state_dict[key]

        if not entry["first_seen"]:
            entry["first_seen"] = event.timestamp

        if event.timestamp - entry["first_seen"] > self.window_secs:
            state_dict[key] = {"ports": set(), "first_seen": event.timestamp, "alerted": False}
            entry = state_dict[key]

        entry["ports"].add(event.port)

        if len(entry["ports"]) >= self.threshold and not entry["alerted"]:
            entry["alerted"] = True
            self._raise_alert(event, src, dst, role, len(entry["ports"]))

    def _raise_alert(self, event, src, dst, role, port_count):
        if role == "probe":
            # attacker = src, target = dst. Check if target already confirmed being probed by src.
            confirm_key = (event.interface, dst, src)
            confirmed = self.confirms.get(confirm_key)
            if confirmed and confirmed["alerted"]:
                print(f"[ALERT][STRONG] Port scan confirmed: {src} → {dst} on {event.interface} "
                      f"({port_count} ports probed, target responses confirm)")
            else:
                print(f"[ALERT] Possible port scan: {src} → {dst} on {event.interface} ({port_count} ports probed)")

        elif role == "confirm":
            # src = target (sending RSTs), dst = attacker
            probe_key = (event.interface, dst, src)
            probed = self.probes.get(probe_key)
            if probed and probed["alerted"]:
                print(f"[ALERT][STRONG] Port scan confirmed: {dst} → {src} on {event.interface} "
                      f"({port_count} ports, target responses confirm)")
            else:
                print(f"[ALERT] {src} showing high refusal rate toward {dst} on {event.interface} "
                      f"({port_count} distinct ports) — possible scan target")