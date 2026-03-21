# XDP Least-Connections NAT Load Balancer

A high-performance Layer-4 NAT based load balancer built in the XDP/eBPF fast path, providing stateful connection-aware scheduling with full NAT semantics.

The dataplane performs connection tracking, backend selection, and bidirectional address rewriting entirely before packets enter the Linux networking stack, enabling low-latency and high-throughput load distribution under heavy connection concurrency.

The system supports both Least-Connections (LC) and Weighted Least-Connections (WLC) scheduling, each available with selectable connection accounting modes. It is structured as a long-running daemon that loads and owns the BPF program, and a separate control CLI that communicates with the daemon at runtime — without ever restarting the dataplane.

Traffic is steered only for configured services, allowing unrelated network flows to pass through the interface unaffected.

> **Why XDP?** Packets are processed before entering the Linux networking stack — minimal CPU overhead, maximum throughput.

---

## Table of Contents

- [Overview](#overview)
- [Key capabilities](#Key-capabilities)
- [Why least connections instead of hashing](#Why-Least-Connections-instead-of-Hash-Based-Load-Balancing)
- [Suitable Deployment Scenarios](#Suitable-Deployment-Scenarios)
- [Scheduling Algorithms](#scheduling-algorithms)
- [Connection Tracking Modes](#connection-tracking-modes)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Building](#building)
- [Running](#running)
- [Runtime CLI](#runtime-cli)
- [Testing](#testing)
- [Customization](#customization)
- [References](#references)

---

## Overview

This project implements a stateful Layer-4 load balancer with full network address translation (NAT) in the eBPF/XDP fast path.
Incoming TCP flows destined for configured virtual service endpoints (VIP–port pairs) are intercepted at the earliest point in the Linux receive path and dynamically steered to backend servers using adaptive connection-aware scheduling.

Unlike stateless hashing-based dataplane designs, the load balancer maintains per-connection state directly inside eBPF maps, enabling real-time backend selection based on active connection counts and configurable backend weights.
Both forward and reverse packet paths are rewritten entirely in the XDP layer, providing complete NAT semantics including source-port translation, symmetric return routing, and deterministic connection teardown handling.

The system is split into three components:

- **`lbxdpd-lc` / `lbxdpd-wlc`** — long-running daemons that load the BPF program, attach it to the network interface, initialise backend state from a config file, and pin the BPF maps to the filesystem so external tools can reach them. The WLC daemon additionally exposes a gRPC control server over a Unix socket for live weight updates.
- **`lbctl`** — a standalone control CLI that reads and writes the pinned BPF maps directly for backend and service operations, and connects to the gRPC socket for weight updates. It requires no daemon restart and works against whichever daemon is currently running.

Because all packet classification, scheduling, connection tracking, and address rewriting occur before socket buffer allocation, the design achieves very low processing latency and high throughput under connection-heavy workloads.

---

## Key Capabilities

- Least-Connections and Weighted Least-Connections scheduling
- In-datapath TCP connection tracking
- Full NAT (forward and reverse path rewriting)
- Multiple virtual services (VIP–port endpoints) with runtime add/remove support
- Runtime backend addition and removal via `lbctl` without dataplane restart
- Live weight updates on WLC backends via gRPC, applied instantly without connection disruption
- Stable traffic distribution under bursty or long-lived connections

Because scheduling decisions are made using real-time connection counts, the load balancer adapts automatically to uneven traffic patterns and backend capacity differences while retaining the performance benefits of early ingress processing with XDP.

The design is suitable for practical high-concurrency environments where stateless hashing leads to load imbalance or poor utilisation fairness.

---

## Why Least-Connections instead of Hash Based Load Balancing

High-performance L4 load balancers in fast datapaths (including most XDP-based designs) commonly rely on **stateless flow hashing** (e.g., 5-tuple hashing) for backend selection.  
Hashing offers constant-time scheduling decisions and minimal per-packet overhead, making it attractive for high-throughput environments.

However, this approach has important practical limitations.

- Hashing assumes that traffic load is **evenly distributed across connections**, which is often not true in real deployments.
- Long-lived or high-throughput persistent connections (such as WebSockets, database sessions, or streaming RPC workloads) can create **significant load imbalance**, even when flow counts appear uniform.
- Stateless hashing cannot adapt to runtime backend load conditions because flow-to-backend mapping is deterministic for the lifetime of the connection.

A further challenge arises when **backend capacity changes dynamically**.

- Adjusting backend weights in a hashing-based scheduler typically requires **rehashing or remapping flows**, which can lead to:
  - sudden traffic shifts
  - connection churn
  - cache and state disruption on backends
- Incremental or fine-grained runtime weight updates are therefore difficult to apply without affecting existing traffic distribution.

This project explores **stateful least-connections scheduling implemented directly in the XDP datapath**, enabling adaptive backend selection based on live connection counts and configurable backend weights.

By maintaining lightweight per-connection state in eBPF maps, the load balancer:

- reacts to real-time load imbalance instead of relying on static flow distribution  
- supports dynamic backend addition, removal, and weight updates without rehashing existing connections  
- performs scheduling entirely in the fast path without requiring backend-side load reporting  

This design trades modest state-management overhead for **improved utilisation fairness, smoother weight transitions, and better handling of persistent or skewed workloads**, while still benefiting from the high throughput of XDP-based packet processing.

---
## Suitable Deployment Scenarios
- Backend identity must remain private : Full NAT hides real server IPs and prevents clients from directly addressing backend nodes.
- Controlled ingress or gateway-style deployments : Centralised entry point simplifies firewalling, policy enforcement, and network segmentation.
- Persistent or long-lived connection workloads : Better distribution than hash-based scheduling for WebSockets, streaming services, or database sessions.
- Heterogeneous backend capacity : Weighted least-connections enables proportional load distribution across unequal servers.

High concurrent connection environments
XDP fast-path processing keeps per-packet overhead low even with stateful scheduling.
---

## Scheduling Algorithms

| Algorithm | Description |
|-----------|-------------|
| **Least Connections (LC)** | Assigns each new connection to the backend with the fewest active connections. All backends are treated equally. |
| **Weighted Least Connections (WLC)** | Assigns connections based on `active_connections / weight`. Backends with higher weights receive a proportionally larger share of traffic. |

---

## Connection Tracking Modes

Both algorithms are available in two builds, differing only in *when* a connection is counted:

| Mode | Counts on | Pros | Cons |
|------|-----------|------|------|
| **SYN** | SYN packet arrival | Reserves backend immediately; more even distribution during bursts | Incomplete handshakes are briefly counted until cleaned up |
| **Established** | First non-SYN packet (after handshake completes) | Counters reflect only fully established connections | Under burst load, multiple SYNs may see stale counters before they update |

---

## Repository Structure
```
.
├── bpf/                        # eBPF/XDP load balancer programs (C)
│   ├── lb_lc_est.c             # LC, established-mode
│   ├── lb_lc_syn.c             # LC, SYN-mode
│   ├── lb_wlc_est.c            # WLC, established-mode
│   └── lb_wlc_syn.c            # WLC, SYN-mode
├── cmd/
│   ├── lbxdpd-lc/              # LC daemon (loads BPF, pins maps, gRPC control)
│   ├── lbxdpd-wlc/             # WLC daemon (loads BPF, pins maps, gRPC control)
│   └── lbctl/                  # CLI — talks to pinned maps and gRPC socket
├── configs/
│   ├── backends_lc.json        # Initial service + backend config for LC
│   └── backends_wlc.json       # Initial service + backend config for WLC (with weights)
├── proto/
│   └── control.proto           # gRPC service definition
└── scripts/
    ├── build.sh                 # Builds all binaries
    ├── gen.sh                   # Regenerates eBPF and protobuf bindings
    └── llvm.sh                  # Installs LLVM toolchain dependencies
```

The system is split into three binaries:

| Binary | Role |
|--------|------|
| `lbxdpd-lc` | LC daemon — loads the BPF program, attaches XDP, pins maps, exposes gRPC |
| `lbxdpd-wlc` | WLC daemon — same as above, adds weight-update support over gRPC |
| `lbctl` | Control CLI — reads pinned maps directly for backend/service operations; uses gRPC for live weight updates (WLC only) |

---

## Prerequisites

Install LLVM and required toolchain dependencies:
```bash
sudo ./scripts/llvm.sh
```

> **Requirements:** Root privileges, a modern Linux kernel with eBPF and XDP support.

---

## Configuration

The load balancer is configured at startup using a JSON file specifying the virtual service endpoint (VIP + port) and the initial backend pool. Backends and services can also be added, removed, or reweighted live via `lbctl` after startup.

### LC — `configs/backends_lc.json`
```json
{
  "service": {
    "vip": "10.45.179.173",
    "port": 8000
  },
  "backends": [
    { "ip": "10.45.179.166", "port": 8000 },
    { "ip": "10.45.179.99",  "port": 8000 }
  ]
}
```

### WLC — `configs/backends_wlc.json`
```json
{
  "service": {
    "vip": "10.45.179.173",
    "port": 8000
  },
  "backends": [
    { "ip": "10.45.179.166", "port": 8000, "weight": 80 },
    { "ip": "10.45.179.99",  "port": 8000, "weight": 20 }
  ]
}
```

---

## Building
```bash
./scripts/gen.sh
./scripts/build.sh
```

This produces three binaries in `bin/`:

| Binary | Description |
|--------|-------------|
| `lbxdpd-lc` | LC daemon |
| `lbxdpd-wlc` | WLC daemon |
| `lbctl` | Control CLI |

---

## Running

Start the daemon first. It loads the BPF program, attaches it to the interface, and pins the maps so `lbctl` can reach them.

**LC:**
```bash
sudo ./bin/lbxdpd-lc -i <interface> -mode syn -config configs/backends_lc.json
sudo ./bin/lbxdpd-lc -i <interface> -mode est -config configs/backends_lc.json
```

**WLC:**
```bash
sudo ./bin/lbxdpd-wlc -i <interface> -mode syn -config configs/backends_wlc.json
sudo ./bin/lbxdpd-wlc -i <interface> -mode est -config configs/backends_wlc.json
```

Replace `<interface>` with the interface to attach to (e.g. `eth0`, `wlo1`).

The recommended mode is `-mode syn` for bursty workloads. Use `-mode est` for stable, long-lived connection workloads.

Once the daemon is running, use `lbctl` in a separate terminal.

---

## Runtime CLI — Structured Reference

### Backend operations

| Command | Syntax | Mode | Description | Notes |
|--------|--------|------|-------------|------|
| Add backend | `sudo ./bin/lbctl add <ip> <port> [weight]` | LC + WLC | Inserts a backend server into the pinned BPF backend map | `weight` ignored in LC mode |
| Delete backend | `sudo ./bin/lbctl del <ip> <port>` | LC + WLC | Removes backend from map | Refused if active connections > 0 |
| List backends | `sudo ./bin/lbctl list` | LC + WLC | Displays backend index, IP, port, connection count, and weight (if WLC) | Reads from pinned maps |

---

### Service (VIP) operations

| Command | Syntax | Mode | Description | Notes |
|--------|--------|------|-------------|------|
| Add service | `sudo ./bin/lbctl addsvc <vip> <port>` | LC + WLC | Registers a virtual service endpoint (VIP:port) | Stored in services BPF map |
| Delete service | `sudo ./bin/lbctl delsvc <vip> <port>` | LC + WLC | Deregisters the VIP entry | |
| List services | `sudo ./bin/lbctl listsvc` | LC + WLC | Lists all configured VIPs | |

---

### Weight control (runtime scheduling update)

| Command | Syntax | Mode | Description | Notes |
|--------|--------|------|-------------|------|
| Update backend weight | `sudo ./bin/lbctl weight <ip> <port> <weight>` | WLC only | Sends gRPC request to daemon to update backend scheduling weight | Uses Unix domain socket control channel |

---

### Program attachment verification

| Purpose | Command | Description |
|--------|--------|-------------|
| Verify XDP program attached | `sudo bpftool prog show` | Lists loaded BPF programs and their attach points |

---

### Operational constraint

| Condition | Behaviour |
|-----------|-----------|
| Backend has active connections | `del` command is rejected |
| Safe removal procedure | Wait for connection drain or stop new flows before deletion |

---

## Testing

To test connection tracking, connections need to persist for some time. The `socat` tool is ideal for this — it keeps connections alive without sending large amounts of data.

### 1. Start backend servers

Run this on each backend machine:
```bash
socat TCP-LISTEN:8000,reuseaddr,fork EXEC:/bin/cat
```

### 2. Send a single request
```bash
socat - TCP:<load_balancer_ip>:8000
```

### 3. Simulate high concurrency
```bash
for i in $(seq 1 100); do
  socat - TCP:<load_balancer_ip>:8000 &
done
```

### 4. Check active kernel TCP connections
```bash
ss -tan '( sport = :8000 )' | wc -l
```

### 5. Observe backend distribution
```bash
sudo ./bin/lbctl list
```

Under burst load, the SYN variants distribute more evenly than the established variants because counters are incremented immediately on SYN arrival. With WLC, backends with higher weights absorb a proportionally larger share of connections.

---

## Customization

The load balancer currently handles a maximum of 60000 simultaneous connections. To change this, modify the constants in the BPF program:
```c
#define MAX_CONNECTIONS 60000
#define MAX_PORT 61024
```

And the corresponding value in the daemon's `ports.go`:
```go
const maxPort = 61024
```

---

## References

- [Teodor Podobnik – XDP Load Balancer Tutorial](https://labs.iximiuz.com/tutorials/xdp-load-balancer-700a1d74)
- [iximiuz Labs – Practical Linux networking and eBPF tutorials](https://labs.iximiuz.com/)
