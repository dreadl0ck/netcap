---
description: Discover record types and distinguish parsing, classification and evidence.
---

# Audit records

Discover the installed decoder inventory and a file's actual fields:

```sh
net capture -overview
net util -decoders
net dump -read analysis/HTTP.ncap.gz -header
net dump -read analysis/HTTP.ncap.gz -fields
```

The authoritative definitions are the release's
[`types/netcap.proto`](https://github.com/dreadl0ck/netcap/blob/v0.15.2/types/netcap.proto).
This avoids hand-maintained counts that confuse record types, nested protobuf
messages, packet decoders and port registrations.

## Correlation and security outcomes

| Contract | Current behavior |
| --- | --- |
| CommunityID | Community ID v1, seed 0; TCP/UDP/SCTP use the observed effective transport after IPv6 extensions. Missing transport ports do not become a zero-port TCP tuple. ICMP keeps its specified paired-message mapping. |
| Stream records | Kerberos, TACACS, IPP, Zabbix, Protobuf, OPCUA, S7Comm and PROFINET copy the conversation ID. Their CSV exports, plus HTTP/DNS, append `CommunityID`; existing columns keep their position. |
| Observation scope | A tuple hash is not a unique session ID. Retain capture RunID, scope/record witnesses and observation boundaries for tuple reuse, VLAN/interface collisions and NAT. |
| Protobuf direction | Response records name the server as sender, with server-side capture time; the generic decoder does not implement HTTP/2 gRPC framing. |
| RDP requested versus selected | `RequestedProtocolsFlags/Names` describe the offer. `UsesTLS/NLA/CredSSP` describe only an observed server-selected protocol when `NegotiatedSecurityKnown` is true. |
| RDP outcomes | `NegotiationOutcome` distinguishes accepted, rejected, not-observed, malformed and unavailable-after-capture-loss. `AuthenticationOutcome` remains unknown: this negotiation decoder has no login-result evidence. |
| Legacy RDP boolean | `ConnectionSuccessful` retains its historical negotiation-acceptance meaning for compatibility. It is not proof of a login; new rules/UI should use the explicit outcome fields. Missing new fields on retained output are legacy/unknown. |
| Certificates | Capture-time validity, cryptographic self-signature state and actual sender are qualified explicitly; see [certificate assessments](tls-fingerprinting.md#certificate-observation-and-assessment). |

The additive protobuf fields remain readable alongside old records. Append-only
CSV evolution still requires position-based consumers and feature matrices to
check their exact header/schema before ingestion (`types/netcap.proto`).

## Record families

| Family | Examples | Interpretation |
| --- | --- | --- |
| Packet layers | Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS | Decoded packet fields; visibility depends on link type and captured bytes |
| Reassembled protocols | HTTP, TLS, SSH, SMTP/IMAP/POP3, SMB, LDAP, Kerberos, DCE/RPC, FTP | Messages/transactions from streams, with protocol-specific limits |
| OT and routing | Modbus, DNP3, S7Comm, CIP/ENIP, OPCUA, PROFINET, BACnet, BGP | Typed observations, not universal device/model support |
| Network summaries | Connection, Host, DeviceProfile, Service, Software | Aggregates and derived claims; review scope, timing and provenance |
| Detection/evidence | Alert, Vulnerability, Exploit, File, Secret | Match or extracted evidence; presence is not an exploitation/execution verdict |

## Important boundaries

| Feature | What is supported |
| --- | --- |
| HTTP | HTTP/1.0/1.1 message/transaction parsing; do not infer HTTP/2/3 decoding from a port or DPI label |
| QUIC | Recognized Initial packet processing and ClientHello extraction; not arbitrary HTTP/3 plaintext |
| TLS | Handshake/certificate/fingerprint metadata without decryption; supplied secrets plus external `tshark` are a separate workflow |
| Service identity | Bounded SSH/HTTP/SMTP/FTP greeting parsers; IANA port names are a separate lookup |
| Vulnerabilities | Structured CPE applicability from schema-2 NVD data; unknown prerequisites remain unknown |
| Identity | Observed host/account facts and conflicts; directory traffic does not automatically identify the server as the subject |

Packet decoders can be selected with `-include`/`-exclude`; names come from
`capture -overview`. Disabling a producer can remove the records downstream
enrichment or detection needs. A missing file or empty output does not certify
absence of the protocol in truncated, encrypted or unrecognized traffic.

## Fields and timing

Use exact case-sensitive protobuf names from `dump -fields`; do not transpose a
TCP field into a Connection rule. For example, TCP ports are numeric while
Connection port fields are strings. Raw capture timestamps use Unix nanoseconds;
display formatting is separate. Stream records may appear on completion and
out of capture-time order. [Dump ordering](filtering-and-export.md) and
[reassembly](reassembly.md) explain the implications.
