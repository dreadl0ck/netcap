# Missing Protocol Support

Protocols present in [The Ultimate PCAP](https://weberblog.net/the-ultimate-pcap/) (v20260316) but not yet producing dedicated audit records in netcap.

## Routing & Redundancy

| Protocol | Frames | Description | Implementation |
|----------|--------|-------------|----------------|
| VRRP | 818 | Virtual Router Redundancy Protocol | Add `decoder/packet/vrrp.go` — gopacket has `layers.LayerTypeVRRP`, decode priority, virtual router ID, IP addresses |
| PIM v1/v2 | 384 | Protocol Independent Multicast | Add `decoder/packet/pim.go` — gopacket may need custom layer, extract version, type, group addresses |

## Network Telemetry & Monitoring

| Protocol | Frames | Description | Implementation |
|----------|--------|-------------|----------------|
| NetFlow v9 | 196 | Cisco flow telemetry | Add `decoder/packet/netflow.go` — parse flow records with template-based decoding; gopacket does not have built-in support, needs custom UDP parser on port 2055/9995 |
| Zabbix | 150 | Monitoring agent protocol | Already decoded as TCP stream by netcap (port 10050/10051); add `decoder/stream/zabbix/` for structured audit records |

## Name Resolution & Discovery

| Protocol | Frames | Description | Implementation |
|----------|--------|-------------|----------------|
| LLMNR | 18 | Link-Local Multicast Name Resolution | Add `decoder/packet/llmnr.go` — DNS-like format on UDP 5355, reuse DNS parsing logic |
| CLDAP | varies | Connectionless LDAP (UDP 389) | Add `decoder/packet/cldap.go` — used for AD domain discovery, parse ASN.1 BER on UDP |

## Authentication

| Protocol | Frames | Description | Implementation |
|----------|--------|-------------|----------------|
| TACACS+ | 18 | Terminal Access Controller Access-Control System | Add `decoder/stream/tacacs/` — TCP port 49, encrypted payload (key known: `John3.16`), extract authentication requests/responses |
| Kerberos | 268 | Kerberos v5 authentication | Credential harvesters exist but no dedicated audit record; add `decoder/stream/kerberos/` to produce structured Kerberos.ncap.gz with ticket types, principals, encryption types |

## Application Layer

| Protocol | Frames | Description | Implementation |
|----------|--------|-------------|----------------|
| DCE/RPC | 420 | Distributed Computing Environment / Remote Procedure Call | Partially captured within SMB records; add standalone `decoder/stream/dcerpc/` for non-SMB DCE/RPC (e.g., EPM, DRSUAPI) |
| IPP | 38 | Internet Printing Protocol | Add `decoder/stream/ipp/` — HTTP-based on port 631, extract printer names, jobs, capabilities |
| OCSP | 29 | Online Certificate Status Protocol | Add `decoder/packet/ocsp.go` — HTTP-based, extract certificate serial, status (good/revoked/unknown), responder |
| STUN | 22 | Session Traversal Utilities for NAT | Add `decoder/packet/stun.go` — UDP port 3478, parse message type, transaction ID, attributes (MAPPED-ADDRESS for NAT detection) |

## Layer 2

| Protocol | Frames | Description | Implementation |
|----------|--------|-------------|----------------|
| HomePlug AV | varies | Powerline networking | Low priority — niche protocol, no gopacket support |
| IS-IS | varies | Intermediate System to Intermediate System | Add `decoder/packet/isis.go` — L2 routing protocol used in ISP/DC networks |
| RARP | varies | Reverse Address Resolution Protocol | Add `decoder/packet/rarp.go` — similar to ARP, legacy protocol |

## Implementation Priority

### High (commonly useful, existing gopacket support)
1. **VRRP** — simple packet decoder, gopacket layer exists
2. **LLMNR** — reuse DNS parsing, important for Windows networks
3. **Kerberos audit records** — harvester exists, needs structured output
4. **STUN** — important for VoIP/WebRTC analysis

### Medium (useful, moderate effort)
5. **TACACS+** — network authentication, encrypted but key often known
6. **NetFlow v9** — valuable for flow analysis, needs template engine
7. **DCE/RPC** — Windows AD analysis
8. **OCSP** — TLS certificate validation chain
9. **IPP** — printer enumeration

### Low (niche use cases)
10. **PIM** — multicast routing
11. **Zabbix** — monitoring traffic
12. **CLDAP** — AD discovery
13. **HomePlug AV** — powerline
14. **IS-IS** — ISP routing
15. **RARP** — legacy

## Verification

Each protocol implementation should be verified against `tests/The Ultimate PCAP v20260316.pcapng`:
1. Run netcap on the PCAP
2. Verify the new `.ncap.gz` file is produced with correct record count
3. Cross-reference record count with `tshark -Y <protocol> | wc -l`
4. Spot-check 2-3 records against tshark field extraction
