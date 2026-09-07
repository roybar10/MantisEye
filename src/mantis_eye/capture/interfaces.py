import subprocess
from scapy.all import get_if_list

def get_bridge_members():
    """Return a set of interfaces that are members of any bridge."""
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
    interfaces = [i for i in get_if_list() if i != "lo"]
    if not interfaces:
        raise RuntimeError("No suitable network interfaces found.")
    bridge_members = get_bridge_members()
    return [i for i in interfaces if i not in bridge_members]