# XDP Least-Connections Load Balancer

This project implements a **NAT-based TCP load balancer using eBPF at the XDP layer**.  
It distributes incoming connections across backend servers using the **least-connections scheduling algorithm**.

Running the load balancer at **XDP (eXpress Data Path)** allows packets to be processed **before entering the Linux networking stack**, reducing overhead and achieving **very low latency packet forwarding**.

---

## Overview

The load balancer performs **connection-aware traffic distribution** using the following mechanism:

- Each incoming TCP connection is assigned to the backend server with the **lowest number of active connections**.
- Active connections are tracked using **TCP packet flags**.
- Packet processing happens in an **XDP eBPF program**, enabling fast packet inspection and redirection.
- The program performs **NAT-based redirection** to selected backend servers.

This design avoids most of the traditional kernel networking stack overhead, allowing the load balancer to operate with **minimal latency and CPU cost**.

---

## Features

- XDP-based packet processing using eBPF  
- Least-connections load balancing algorithm
- NAT-based backend redirection
- Dynamic backend management through CLI commands
- Connection tracking using TCP flags
- Runtime backend configuration via JSON file

---

## Architecture

```
Client
   │
   ▼
XDP eBPF Program
   │
   │  (least-connections scheduling)
   ▼
Selected Backend Server
```

The eBPF program runs directly at the **XDP hook on the network interface**, enabling packet handling immediately upon reception.

---

## Configuration

Initial backend servers are defined in:

```
configs/backends.json
```

Example:

```json
{
  "backends": [
    "10.0.0.2",
    "10.0.0.3"
  ]
}
```

Backends can also be **added or removed dynamically at runtime** through CLI commands.

---

## Running the Load Balancer

From the repository root:

```bash
go generate ./cmd/lb
go build -o lb ./cmd/lb
sudo ./lb -i <network-interface> -config configs/backends.json
```

Example:

```bash
sudo ./lb -i wlo1 -config configs/backends.json
```

---

## Runtime CLI Commands

The load balancer exposes an interactive CLI:

```
lb>
```

Available commands:

```
add <ip>     Add a backend server
del <ip>     Remove a backend server
list         List current backends and connection counts
```

Example:

```
lb> add 10.0.0.4
lb> del 10.0.0.3
lb> list
```

---

## Observing eBPF Programs

You can inspect the loaded XDP program using:

```bash
sudo bpftool prog show
```

This allows verification that the eBPF program is attached and running.

---

## Testing the Load Balancer

### 1. Start backend servers

On each backend machine:

```bash
python3 -m http.server 8000
```

---

### 2. Send requests to the load balancer

From a client machine:

```bash
curl -v --http1.1 http://<load-balancer-ip>:8000
```

Using HTTP/1.1 ensures the connection remains open for a short period.

Each connection typically persists for **10–15 seconds**, making it easier to observe the connection tracking behavior.

---

## Experimenting with Load Balancing

You can experiment by:

- Creating multiple concurrent connections
- Closing connections in different orders
- Adding or removing backend servers dynamically

Observe how the **least-connections algorithm redistributes traffic** as connection counts change.

---

## Customization

Currently, the program balances traffic **only for TCP port 8000**.

This can be modified directly in the eBPF program:

```
bpf/lb.c
```

By adjusting the port filter, the load balancer can be adapted for other services.

---

## Repository Structure

```
bpf/            eBPF/XDP load balancer program
cmd/lb/         Go user-space loader and CLI
configs/        Backend configuration file
scripts/        Utility scripts
```

---

## Technologies Used

- eBPF
- XDP (eXpress Data Path)
- Go
- Linux networking

---

## Notes

- Root privileges are required to attach XDP programs.
- The system must support **eBPF and XDP** (modern Linux kernel recommended).
