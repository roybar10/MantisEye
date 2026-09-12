"""Interface discovery for the sniffer.

Excludes bridge-member interfaces at runtime rather than hardcoding them, since
which interfaces are bridged can change between Mininet runs (or, on a real
router, between reboots/reconfigs). Sniffing on br-lan alone is sufficient and
avoids double-counting the same packet on both a member interface and the bridge.
"""

import subprocess
from scapy.all import get_if_list

def get_bridge_members():
  """Return the set of interface names currently enslaved to any bridge.

    Queries `ip -o link show` and looks for a "master" token, which the kernel
    reports for any interface that's a bridge/bond member. This is queried live
    (not cached) so it stays correct if bridge membership changes at runtime.

    Returns:
        set[str]: Interface names that are bridge members.
    """
    
    members = set()
    try:
        output = subprocess.check_output(["ip", "-o", "link", "show"], text=True)
        for line in output.splitlines():
            if "master" in line:
                iface = line.split(":")[1].strip().split("@")[0]
                members.add(iface)
    except subprocess.CalledProcessError:
        pass
    return members

def detect_interfaces():
    """Return interfaces safe to sniff on: everything except loopback and bridge members.

    Raises:
        RuntimeError: If no suitable interfaces are found (e.g. topology not up yet).

    Returns:
        list[str]: Interface names to pass to sniff().
    """
    
    interfaces = [i for i in get_if_list() if i != "lo"]
    if not interfaces:
        raise RuntimeError("No suitable network interfaces found.")
    bridge_members = get_bridge_members()
    return [i for i in interfaces if i not in bridge_members]