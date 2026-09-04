import time
from collections import defaultdict
from mantis_eye.capture.events import PacketEvent

class PortScanDetector:
    def __init__(self, window_secs=30, threshold=5):
        self.window_secs = window_secs
        self.threshold = threshold
        self.state = defaultdict(lambda: {"ports": set(), "first_seen": None})
    
    def __call__(self, event: PacketEvent):
        if event.port is None:
            return
        
        key = (event.interface, event.src_ip, event.dst_ip)
        entry = self.state[key]
        
        if not entry["first_seen"]:
            entry["first_seen"] = event.timestamp
        
        # Expire old entries
        if event.timestamp - entry["first_seen"] > self.window_secs:
            self.state[key] = {"ports": set(), "first_seen": event.timestamp}
            entry = self.state[key]
        
        entry["ports"].add(event.port)
        
        if len(entry["ports"]) >= self.threshold:
            print(f"[ALERT] Port scan detected: {event.src_ip} → {event.dst_ip} on {event.interface} ({len(entry['ports'])} ports)")
            self.state[key] = {"ports": set(), "first_seen": None}  # Reset