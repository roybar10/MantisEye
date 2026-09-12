"""Re-exports detectors so dispatcher.py can do a single package-level import
(`from mantis_eye.detection import detectors`) instead of one import line per
detector as the package grows."""
from .port_scan import PortScanDetector
from .arp_spoof import ArpSpoofDetector