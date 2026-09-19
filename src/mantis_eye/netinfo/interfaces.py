"""Interface discovery for the sniffer.

Excludes bridge-member interfaces at runtime rather than hardcoding them, since
which interfaces are bridged can change between Mininet runs (or, on a real
router, between reboots/reconfigs). Sniffing on br-lan alone is sufficient and
avoids double-counting the same packet on both a member interface and the bridge.
"""

import subprocess
import ipaddress
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

def get_wan_interface() -> str | None:
    """Returns the interface owning the default route, or None if there
    isn't one. Used to exclude WAN from LAN-scoped detectors like ARP
    spoofing, without hardcoding an interface name — this holds regardless
    of what the bridge or uplink happens to be called.
    """
    try:
        output = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True
        )
    except subprocess.CalledProcessError:
        return None
    for line in output.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    return None

def detect_lan_interfaces() -> list[str]:
    """Returns every sniffable interface except WAN — one entry per LAN
    segment. On a flat single-bridge topology this is a list of one
    (e.g. ["br-lan"]); on a router with multiple LANs/VLANs, each gets its
    own entry, and ARP spoofing is checked independently per segment.
    """
    wan = get_wan_interface()
    return [i for i in detect_interfaces() if i != wan]

def get_interface_network(iface):
    """Return the IPv4 network (ipaddress.IPv4Network) that iface's address
    belongs to, or None if the interface has no address or lookup fails.
    """
    try:
        output = subprocess.check_output(["ip", "-o", "-4", "addr", "show", "dev", iface], text=True)
        cidr = output.split()[3]
        return ipaddress.ip_interface(cidr).network
    except (subprocess.CalledProcessError, IndexError, ValueError):
        return None