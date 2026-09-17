"""DHCP lease-file discovery — locates the dnsmasq lease file so callers
can treat DHCP leases as an authoritative binding source.
"""

import os

_DHCP_LEASE_CANDIDATES = [
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/dhcp/dnsmasq.leases",
    "/tmp/dnsmasq.leases",
]


def find_dhcp_lease_file():
    for path in _DHCP_LEASE_CANDIDATES:
        if os.path.exists(path):
            return path
    return None