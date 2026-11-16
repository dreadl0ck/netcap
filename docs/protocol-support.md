---
description: List the record types Netcap writes and how to read them.
---

# Audit records

List the decoders in your build and the fields of a record file:

```sh
net capture -overview
net util -decoders
net dump -read analysis/HTTP.ncap.gz -header
net dump -read analysis/HTTP.ncap.gz -fields
```

The record definitions are in [`types/netcap.proto`](https://github.com/dreadl0ck/netcap/blob/master/types/netcap.proto). Use the revision that matches your binary, because newer revisions add fields.

## Correlation and security outcomes

| Topic                      | How it works                                                                                                                                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CommunityID                | Community ID v1 with seed 0. For TCP, UDP and SCTP it uses the transport protocol found after any IPv6 extension headers. A packet without ports does not get a zero-port TCP tuple. ICMP pairs request and reply.       |
| Stream records             | Kerberos, TACACS, IPP, Zabbix, Protobuf, OPCUA, S7Comm and PROFINET records carry the conversation ID. Their CSV output, like HTTP and DNS, ends with a `CommunityID` column. Existing columns keep their position.      |
| Observation scope          | A tuple hash is not a unique session ID. Tuples get reused, and VLANs, interfaces and NAT can produce collisions. Keep the capture run ID and scope information with the records.                                        |
| Protobuf direction         | In a response record the sender is the server and the timestamp is the server's capture time. The generic decoder does not parse HTTP/2 gRPC framing.                                                                    |
| RDP requested vs selected  | `RequestedProtocolsFlags` and `RequestedProtocolsNames` hold what the client offered. `UsesTLS`, `UsesNLA` and `UsesCredSSP` describe the protocol the server selected, and only when `NegotiatedSecurityKnown` is true. |
| RDP outcomes               | `NegotiationOutcome` is accepted, rejected, not observed, malformed, or unavailable because of capture loss. `AuthenticationOutcome` stays unknown, because the negotiation decoder never sees the login result.         |
| RDP `ConnectionSuccessful` | Means the negotiation was accepted, not that a login succeeded. Use the outcome fields in new rules and views. Records from older captures may lack the newer fields, which means unknown.                               |
| Certificates               | Validity at capture time, self-signature and the actual sender are reported separately. See [certificate assessments](tls-fingerprinting.md#certificate-observation-and-assessment).                                     |

CSV columns are only ever appended. If you read CSV by column position or use feature matrices, check the header of each file before you ingest it.

## Record families

| Family                 | Examples                                                          | Notes                                                                 |
| ---------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------- |
| Packet layers          | Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS, NBNS, IEEE802154   | Decoded packet fields. What you see depends on link type and snaplen. |
| Reassembled protocols  | HTTP, TLS, SSH, SMTP/IMAP/POP3, SMB, LDAP, Kerberos, DCE/RPC, FTP | Messages and transactions rebuilt from streams                        |
| OT and routing         | Modbus, DNP3, S7Comm, CIP/ENIP, OPCUA, PROFINET, BACnet, BGP      | Records for the listed protocols, not every device or model           |
| Network summaries      | Connection, Host, DeviceProfile, Service, Software                | Aggregates and derived values. Check scope and timing.                |
| Detection and evidence | Alert, Vulnerability, Exploit, File, Secret                       | A match or extracted item. It does not show that an exploit worked.   |

## Protocol details

| Feature          | What is decoded                                                                                                                                                                                                                                |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| HTTP/1           | Messages and transactions. [Incremental HTTP/1](reassembly.md#incremental-transactions) needs an observed handshake.                                                                                                                           |
| Cleartext HTTP/2 | The client preface, HPACK headers and h2c upgrades, written as HTTP records. gRPC messages are not decoded.                                                                                                                                    |
| QUIC             | Initial packets and the ClientHello. HTTP/3 content is not decoded.                                                                                                                                                                            |
| TLS              | Handshake, certificate and fingerprint metadata. If the PCAPNG contains a TLS key log, TLS 1.2 and 1.3 HTTP traffic with supported AEAD suites is decrypted.                                                                                   |
| IEEE 802.15.4    | MAC beacon, data, ACK and command frames on link types 195 and 230, with PAN and address fields, 2015 sequence suppression and FCS checks. Uncompressed 6LoWPAN IPv6 is decoded. Protected and IPHC payloads are named in `PayloadProtocol`.   |
| Service identity | Greeting parsers for SSH, HTTP, SMTP and FTP. IANA port names are a separate lookup.                                                                                                                                                           |
| Vulnerabilities  | CPE matching from NVD schema 2 data. If a prerequisite is unknown, the result stays unknown.                                                                                                                                                   |
| Identity         | `Hosts.json` keeps host profiles, NBNS registrations and browser names. `.local` aliases are merged. PTR owners and domain browser names are not treated as hostnames, and a directory server in the traffic is not assumed to be the subject. |

## Capture link framing

`LinkFrame` records validated non-IP capture headers, bounded metadata and exact
header bytes. `PayloadProtocol: "opaque"` and `Qualifications` name the limits;
accepting a link header does not mean its application protocol was decoded.
`-payload` adds captured payload bytes to these records.

| Link type | Framing and downstream decoding |
| --- | --- |
| 3, AX.25 | Bounded destination/source/digipeater chain and control/PID fields; UI IPv4 payloads reach the IP decoder. Extended control mode is not inferred |
| 165, BACnet MS/TP | Preamble, frame type, bus addresses and declared data/trailer bounds. Header CRC8 and non-COBS data CRC16 have explicit validity fields; invalid checksums retain wire evidence. COBS CRC32K, NPDU/APDU and proprietary bodies remain opaque |
| 187/201, Bluetooth HCI H4 | Packet indicator, command/event/ACL/SCO/ISO lengths and optional direction pseudo-header. HCI payloads remain opaque |
| 209, Linux I2C | Six-byte bus/event/flags/address header, using network byte order for flags. Payloads remain opaque |
| 243, MPEG-2 TS | Whole 188-byte frames, sync/adaptation bounds and first PID/continuity metadata; elementary streams are not decoded |
| 252, Wireshark Upper PDU | Bounded TLVs, the first protocol selector, raw option evidence and exported address metadata. Known packet dissectors are invoked; heuristic/table selectors and unknown dissectors remain opaque. Exported metadata is not an original Ethernet/IP header |
| 266, Darwin USB | Versioned little-endian URB headers, 64-bit request IDs, bus/device/endpoint/direction, control setup and bounded ISO descriptors; emitted through `USB`/`USBRequestBlockSetup` |
| 289, ATSC ALP | Base/extended headers, substream/extension bounds and declared lengths. Unsegmented IPv4 reaches IP decoding. Segment/concatenation reconstruction, signalling bodies and compressed TS reconstruction remain explicitly opaque |
| 300, MDB | Version/event/address framing, master/peripheral direction and checksum metadata; device-specific transaction fields are not inferred |

Wire references: [tcpdump link registry](https://www.tcpdump.org/linktypes.html),
[Upper PDU TLVs](https://gitlab.com/wireshark/wireshark/-/blob/master/wsutil/exported_pdu_tlvs.h),
[Darwin USB parser](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-usb.c)
and [MDB capture format](https://www.kaiser.cx/pcap-mdb.html).
The tcpdump Darwin diagram labels the request ID as four bytes; the working
layout uses eight bytes at offset 16, with location at 24 and endpoint type at 31
(`TestDarwinUSBHeaderMappingAndSetup`). Submitted ISO descriptors can be 20 bytes;
completed descriptors include the timestamp and require 28 bytes.

## Captured TLS secrets

If a PCAPNG file contains `TLSK` Decryption Secrets Blocks, even after the packets, Netcap reads them before decoding streams. TLS 1.2 and 1.3 with AES-GCM or ChaCha20-Poly1305 are decrypted using the NSS key log secrets. Records that fail authentication, lack a key or use an unsupported suite stay encrypted. Decrypted HTTP records carry `ParseQualifications: ["decrypted-tls-key-log"]`.

Secrets stay in memory during the capture. Retained packet segments do not include the key blocks, so keep the original PCAPNG if you need to decrypt again.

## Cleartext HTTP/2 evidence

Netcap decodes cleartext HTTP/2 sessions that start with the client preface, and HTTP/1.1 upgrades to h2c. Capture and dump the HTTP records as usual:

```sh
net capture -read h2c.pcap -out h2-audit -dpi=false -geoDB=false
net dump -read h2-audit/HTTP.ncap.gz -json
```

| Field or limit           | Meaning                                                                                                                                                     |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Proto`, `HTTP2StreamID` | `HTTP/2.0` and the stream ID. Stream ID 0 can hold a connection-level failure.                                                                              |
| Headers and trailers     | Request and response fields per direction, decoded from HPACK. Gaps and invalid or missing framing show up in `ParseQualifications` and `ReassemblyStatus`. |
| Framing limits           | 64 KiB per frame, 16 KiB HPACK table, 128 active streams, 4,096 transactions and 100,000 frames per conversation                                            |
| Retained data            | 1 MiB per body, 8 MiB of bodies in total, 2 MiB of headers in total. These limit the parser, not process memory.                                            |
| Encrypted traffic        | TLS and QUIC traffic is not decoded this way. An `application/grpc` content type does not mean protobuf messages were decoded.                              |

The firewall's live gRPC and HTTP/3 handling is a separate feature.

Select packet decoders with `-include` and `-exclude`. The names come from `capture -overview`. Turning off a decoder also removes the records that enrichment and detection rely on. No output for a protocol can mean it was absent, truncated, encrypted or not recognised.

## Fields and timing

Field names are case-sensitive and come from `dump -fields`. Don't carry a TCP field over to a Connection rule: TCP ports are numbers and Connection ports are strings. Timestamps are Unix nanoseconds, and display formatting is separate. Stream records are often written when the stream completes, so they can appear out of capture-time order. [Dump ordering](filtering-and-export.md) and [reassembly](reassembly.md) cover this.
