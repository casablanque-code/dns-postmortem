# dns-postmortem

**Network Forensics Series** · Part 4 of N

A Rust/WASM tool for post-mortem analysis of DNS traffic captures.
Drop a `.pcap` or `.pcapng` file — get a full forensic report in your browser.

## What it detects

| Anomaly | Description |
|---|---|
| **DNS Tunneling** | Long subdomain labels or NULL/TXT queries consistent with data exfiltration or C2 |
| **DGA Activity** | NXDOMAIN flood within a short window — Domain Generation Algorithm pattern |
| **Subdomain Probing** | Slow persistent NXDOMAIN stream targeting subdomains of a single domain |
| **Rogue Resolver** | Duplicate responses to the same transaction ID from different sources |
| **Unsolicited Response** | Response without a matching query — possible spoofing attempt |
| **Query Timeout** | Queries with no response within the timeout window |
| **Truncated Response** | TC bit set — oversized response, client must retry over TCP |
| **Query Retransmit** | Same query repeated 3+ times — packet loss or unresponsive server |
| **Fast-Flux** | Significant TTL variation for the same domain across multiple responses |

## Parsing notes

- Full RFC 1035 name compression with pointer loop detection (`MAX_PTR_DEPTH = 10`)
- EDNS0 (RFC 6891) OPT record — UDP payload size, version, DO bit
- DNS over TCP with 2-byte length prefix (RFC 1035 §4.2.2)
- Request/response matching by `(txid, client_ip, server_ip)` tuple

## Structure

```
crates/parser/   Rust WASM core
  dns.rs         RFC 1035 + EDNS0 packet parser
  analyzer.rs    Request/response FSM + anomaly detection
  root_cause.rs  Causal chain correlation
  net.rs         IP/UDP/TCP extractor
  pcap.rs        Legacy pcap parser
  pcapng.rs      PCAPng parser

web/             Single-file frontend (HTML/JS/CSS)
dataset/         8 synthetic pcap scenarios
```

## Build

```bash
# Install wasm-pack if needed
cargo install wasm-pack

make build      # release WASM
make check      # cargo check + tests
make dataset    # generate test pcaps (Python stdlib only)
```

## Deploy

```bash
wrangler pages deploy web/
```

## Dataset scenarios

| # | Scenario | Anomaly |
|---|---|---|
| 01 | Clean | Normal queries and responses — baseline |
| 02 | NXDOMAIN Flood | 30 DGA-style queries in under 10 seconds |
| 03 | Slow Probe | Subdomain enumeration across 8 subdomains |
| 04 | DNS Tunneling | Long base32 labels + TXT/NULL queries |
| 05 | Query Timeout | 5 queries to an unreachable server with retransmits |
| 06 | Fast-Flux | Same domain answered with 720x TTL variation |
| 07 | Truncated + TCP | TC bit set, retry over TCP |
| 08 | Unsolicited | Spoofed second response from a rogue source |

## Series

- [ospf-postmortem](https://github.com/casablanque-code/ospf-postmortem) — OSPF FSM reconstruction
- [dhcp-postmortem](https://github.com/casablanque-code/dhcp-postmortem) — DORA FSM + anomaly detection
- [stp-postmortem](https://github.com/casablanque-code/stp-postmortem) — STP topology analysis
- **dns-postmortem** — DNS forensics + tunneling detection ← you are here
