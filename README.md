# dhcp-postmortem

**Network Forensics Series** · Part 2 of N

A Rust/WASM tool for post-mortem analysis of DHCP traffic captures.
Drop a `.pcap` or `.pcapng` file — get a full forensic report in your browser.

## What it detects

| Anomaly | Description |
|---|---|
| **Rogue DHCP Server** | Two Offer responses to a single transaction from different servers |
| **DHCP Starvation** | Discover flood pattern indicating pool exhaustion attack |
| **IP Conflict** | Same IP assigned to two different MAC addresses |
| **Lease Conflict** | ACK for an IP already in active lease |
| **NAK Storm** | Repeated NAK cycle — client stuck in Discover→Request→NAK loop |
| **Server Unreachable** | Discover without Offer within timeout window |

## FSM

RFC 2131 client state machine:

```
Init → Selecting → Requesting → Bound → Renewing → Rebinding → Expired
```

## Structure

```
crates/parser/   Rust WASM core
  dhcp.rs        RFC 2131 + 2132 packet parser
  analyzer.rs    DORA FSM + anomaly detection
  root_cause.rs  Causal chain correlation
  net.rs         IP/UDP extractor
  pcap.rs        Legacy pcap parser
  pcapng.rs      PCAPng parser

web/             Single-file frontend (HTML/JS/CSS)
dataset/         6 synthetic pcap scenarios
```

## Build

```bash
# Install wasm-pack if needed
cargo install wasm-pack

make build      # release WASM
make dev        # dev build (no wasm-opt)
make check      # cargo check only
make dataset    # generate test pcaps (requires scapy)
```

## Deploy

```bash
wrangler pages deploy web/
```

## Dataset scenarios

| # | Scenario | Anomaly |
|---|---|---|
| 01 | Clean DORA | None — baseline |
| 02 | Rogue Server | Two Offer on same xid |
| 03 | Starvation | 50 Discover flood, legit client times out |
| 04 | NAK Storm | Client in 5-cycle NAK loop |
| 05 | Server Unreachable | Discover retransmits, no Offer |
| 06 | IP Conflict | Same IP ACK'd to two MAC addresses |

## Series

- [ospf-postmortem](https://github.com/casablanque-code/ospf-postmortem) — OSPF FSM reconstruction
- **dhcp-postmortem** — DORA FSM + anomaly detection ← you are here
- `stp-postmortem` — planned
