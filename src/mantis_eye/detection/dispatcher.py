from typing import Callable, List
from mantis_eye.capture.events import PacketEvent

class Dispatcher:
    def __init__(self):
        self._detectors: List[Callable[[PacketEvent], None]] = []

    def register(self, detector: Callable[[PacketEvent], None]):
        self._detectors.append(detector)

    def dispatch(self, event: PacketEvent):
        for detector in self._detectors:
            detector(event)