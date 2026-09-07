from collections import defaultdict
from typing import Callable, List
from mantis_eye.capture.events import PacketEvent
from mantis_eye.detection import detectors

class Dispatcher:
    def __init__(self):
        self._detectors_by_proto: dict[str, List[Callable[[PacketEvent], None]]] = defaultdict(list)
        self._register_default_detectors()

    def _register_default_detectors(self):
        self._register(detectors.PortScanDetector(), protos=["tcp"])
        # future detectors get added here, one line each

    def _register(self, detector: Callable[[PacketEvent], None], protos: List[str]):
        for proto in protos:
            self._detectors_by_proto[proto].append(detector)

    def dispatch(self, event: PacketEvent):
        for detector in self._detectors_by_proto.get(event.proto, []):
            detector(event)