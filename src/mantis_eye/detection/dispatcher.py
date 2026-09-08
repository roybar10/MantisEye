"""Owns detector construction and proto-based routing.
Routing is proto-first (defaultdict(list) keyed by event.proto) rather than
"dispatch to every detector and let each self-filter" — so a detector list only
ever contains detectors relevant to that proto, and adding a new detector is a
single registration line, never a change to dispatch() itself."""

from collections import defaultdict
from typing import Callable, List
from mantis_eye.capture.events import PacketEvent
from mantis_eye.detection import detectors

class Dispatcher:
    """Routes PacketEvents to the detectors registered for their protocol."""

    def __init__(self):
        """Build the proto->detectors routing table and register default detectors."""
        self._detectors_by_proto: dict[str, List[Callable[[PacketEvent], None]]] = defaultdict(list)
        self._register_default_detectors()

    def _register_default_detectors(self):
        """Single source of truth for which detectors are active and on which protos.
        Adding a new detector = one line here. No other file needs to change."""
        self._register(detectors.PortScanDetector(), protos=["tcp"])
        # future detectors get added here, one line each

    def _register(self, detector: Callable[[PacketEvent], None], protos: List[str]):
        """Register a detector instance under one or more protocols.
        Args:
            detector: Any callable detector (e.g. PortScanDetector instance),
                invoked as detector(event).
            protos: Protocols this detector should receive events for."""
        
        for proto in protos:
            self._detectors_by_proto[proto].append(detector)

    def dispatch(self, event: PacketEvent):
        """Send an event to every detector registered for its protocol.
        Args:
            event: The parsed PacketEvent to route."""
        
        for detector in self._detectors_by_proto.get(event.proto, []):
            detector(event)