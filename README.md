# MantisEye

A Python-based Network Intrusion Detection System (IDS) built as a portfolio project demonstrating packet capture, real-time anomaly detection, and network architecture design. Built to reflect real engineering judgment, not a toy demo.

## Current Capabilities

- **Packet capture**: Scapy-based sniffer, auto-detects non-loopback/non-bridge-member interfaces to avoid double-counting on bridged setups
- **Event pipeline**: `PacketEvent` → `Dispatcher` (pub-sub) → registered detectors
- **Port scan detection**: correlates SYN bursts (probe) and RST bursts (confirm) between a host pair; escalates to a confirmed alert only when both signals independently cross threshold; tracks ongoing incidents (`NEW` → `CONTINUED` → `STRONG`/confirmed) instead of re-alerting on every packet
- **Verified** end-to-end on a Mininet topology simulating a real home router

## Architecture

- **Capture layer** (`capture/`) — isolates Scapy specifics behind `PacketEvent`, so swapping capture libraries later only requires rewriting `build_event()`
- **Detection layer** (`detection/`) — `Dispatcher` decouples capture from detection logic; detectors are pluggable, stateful, and expire idle state to bound memory growth
- Synchronous, per-packet pipeline (no queue) — deliberate for now; queue-based decoupling deferred until load testing proves it's needed

## Known Limitations

- **Assumes a software-bridged router deployment** (e.g., OpenWrt-style `br-lan`), where the OS itself performs LAN switching and all traffic is visible on the bridge interface.
- **Does not support hardware-switched routers** (dedicated switch ASIC) out of the box — those require manual port-mirroring configuration on the switch to route LAN-to-LAN traffic to the router's CPU for MantisEye to see it. MantisEye does not currently auto-detect router type or auto-configure mirroring.
- In-memory-only state: detection history isn't persisted; a restart loses all tracked incidents.
- Single-process, single-machine deployment; no distributed/multi-sensor support.

## Roadmap

**Near-term:**
- ARP spoofing detector (per-interface state; `build_event()` ARP branch already exists, detector not yet built)
- Harden port scan detector further (tune thresholds, review edge cases)

**Storage & API:**
- Persist incidents to SQLite — decouples detection state from durability; enables historical/forensic queries independent of in-memory tracking
- Retention policy: keep confirmed incidents long-term, shorter TTL for unconfirmed/suspected-only incidents (SIEM-style tiered retention)
- FastAPI layer exposing alerts/incidents over REST

**Dashboard:**
- Frontend framework not yet decided (React/WebSockets under consideration, not started)

**Performance & capture:**
- Migrate capture layer from Scapy to dpkt for performance, once correctness is fully validated on Scapy (PacketEvent's abstraction is designed specifically to make this swap isolated to `build_event()`)
- Revisit synchronous pipeline vs. queue-based decoupling once realistic load-testing data exists

**Deployment generality:**
- Auto-detect bridge vs. hardware-switched deployment (check for `br-lan`-style bridge interfaces at startup)
- On hardware-switched routers, document/automate switch mirroring setup where the underlying switch chip supports it (not all consumer hardware does)

## Development Environment

- VirtualBox VM, Ubuntu/Debian
- VS Code + GitHub Copilot (free tier)
- Python venv (scapy, fastapi, uvicorn)
- Mininet for network simulation (runs on system Python, not venv)