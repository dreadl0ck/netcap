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

`LinkFrame` records non-IP capture framing, exact header bytes and reconstruction
outcomes. `PayloadProtocol: "opaque"` and `Qualifications` name the limits;
accepting a link header does not mean its application protocol was decoded.
`-payload` adds captured payload bytes; MS/TP and signalling also expose their
decoded bodies as `DecodedPayload`. `Payload` always retains the captured form.

| Link type | Framing and downstream decoding |
| --- | --- |
| 3, AX.25 | UI and negotiated I-frame IPv4/ARP dispatch; basic/extended sequence fields require observed SABM/SABME and reverse UA. Unknown control modes/PIDs remain opaque |
| 165, BACnet MS/TP | CRC8/CRC16/COBS/CRC32K; checksum-valid NPDU/APDU metadata shares `internal/bacnet` with BACnet/IP. Frame 34 supports scoped 6LoBAC/IPHC IPv6 dispatch. Unknown contexts, vendor bodies and unreassembled APDU segments are qualified |
| 187/201, Bluetooth HCI H4 | Controller/version/address events, bounded ACL/L2CAP reconstruction, signalling, ATT headers/handles/UUIDs/MTU and SMP pairing metadata. Directionless fragments, SCO/ISO codecs and dynamic channel profiles remain qualified; ATT values and SMP keys are not copied into metadata |
| 209, Linux I2C | Six-byte bus/event/flags/address header; explicit EEPROM-8/EEPROM-16 profiles expose transfer lengths and write address pointers |
| 243, MPEG-2 TS | Continuity-aware PAT/PMT section assembly and CRC32, bounded PES header/PTS/DTS parsing, H.264/H.265 SPS dimensions/profile/level, IDR/IRAP and MPEG-video/AAC-ADTS headers. This is media metadata, not audio/video rendering |
| 252, Wireshark Upper PDU | Known dissectors plus registered `ethertype`, `ip.proto`, `ipv6.nxt`, `udp.port` numeric tables and the bounded `dns_udp` heuristic. The table value must immediately follow the selected table TLV. Unknown selectors stay opaque; exported addresses do not fabricate IP headers |
| 266, Darwin USB | Versioned URB headers, 64-bit IDs, control setup and bounded ISO descriptors; standard device/configuration/string and HID report descriptors are matched to captured control requests. Explicit HID boot profiles decode reports. These profiles also support USB 189/220/249 |
| 289, ATSC ALP | IPv4 segmentation/concatenation, TS restoration, LMT/RDT metadata, JSON/XML validation and bounded DEFLATE. Qualified ROHC UDP profile 0x0002 supports direct IPv4/IPv6 IR/IR-DYN, UO-0/UO-1 and basic UOR-2 with extensions 0/1; tunnel chains, extension lists and extensions 2/3 remain qualified |
| 300, MDB | Direction/checksum metadata; explicit coin-changer/bill-validator profiles identify commands and decode checksum-valid setup replies matched to the preceding request |

Wire references: [tcpdump link registry](https://www.tcpdump.org/linktypes.html),
[Upper PDU TLVs](https://gitlab.com/wireshark/wireshark/-/blob/master/wsutil/exported_pdu_tlvs.h),
[Darwin USB parser](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-usb.c)
and [MDB capture format](https://www.kaiser.cx/pcap-mdb.html).
The tcpdump Darwin diagram labels the request ID as four bytes; the working
layout uses eight bytes at offset 16, with location at 24 and endpoint type at 31
(`TestDarwinUSBHeaderMappingAndSetup`). Submitted ISO descriptors can be 20 bytes;
completed descriptors include the timestamp and require 28 bytes.

## Link reconstruction

Link reconstruction runs before flow sharding (`collector/link_reconstruction.go`).
Each completed IP child enters ordinary normalization, detection and TCP/UDP
processing. Captured-packet counters and retained capture bytes count each original
once; derived flow counters count logical packets and their decoded lengths.

| Contract | Implementation and evidence |
| --- | --- |
| Provenance | `PacketContext.LinkTransformations` carries child ordinals, packet-relative source byte ranges and synthesized-byte descriptions. Capture references retain timestamps and physical lengths; IP defragmentation and backing-store metadata preserve the transformation chain |
| Isolation | Interface/section scope, SID presence/value, available PLP identity and packet type separate assemblies. Without PLP metadata, an interface must represent one ALP stream; no PLP identity is inferred |
| Bounds | Shared 8-MiB retained-state credits, 1,024 assemblies, 32 segments and 65,535 decoded bytes per assembly; these are scoped allocation credits, not an RSS cap |
| Lifecycle | Sequence 0 starts/replaces an assembly. Identical repeats of the previous non-initial segment are ignored; conflicting/out-of-order segments retire it. Expiry uses a monotonic 30-second capture-time window or 4,096 subsequent ingress packets. EOF emits incomplete-reconstruction records and releases state |
| Failure | State-budget exhaustion cancels capture, records an error manifest and prevents readiness (`TestALPExpiryAndBudgetReadiness`). `LinkReconstructionHealth.json` reports limits, peak credits and incomplete outcomes |
| TS reconstruction | At most 16 transmitted TS packets plus 128 declared deleted null packets per ALP frame. Restored sync bytes, common headers/counters and null filler are explicitly marked as synthesized |
| Signalling | Packed LMT entries are bounded to 4,096. Raw DEFLATE output totals at most 1 MiB per ALP payload; XML depth is limited to 64. Generic JSON/XML bodies require `-payload`; default output records format/length validation. Signalled multicast addresses do not create observed IP traffic |

`TestALPDerivedCaptureWorkerInvariance` checks byte/audit equivalence with 1, 2, 4
and 8 workers. `TestALPInsidePPIPreservesAbsoluteSourceRanges` covers nested PPI;
`TestALPDerivedIPFragmentsKeepAllTransformations` covers subsequent IP reassembly.
`TestALPTSReconstruction` compares PIDs and continuity counters with installed
`tshark`; it does not qualify elementary-stream decoding.

MS/TP uses [RFC 8163 Appendices B–D](https://www.rfc-editor.org/rfc/rfc8163.html#appendix-B):
CRC32K covers the encoded data, and the five-byte checksum field is COBS-decoded
separately. `TestMSTPCOBSAndCRC32KRFC8163` checks the published 547-byte wire
example and 533-byte decoded payload. `TestLoBACContextLearningAndRFC8163IPv6`
checks the resulting 558-byte IPv6 packet and ICMPv6 checksum after prefix learning.

| Follow-up | Bounds and qualification |
| --- | --- |
| 6LoBAC | RFC 6282 traffic/address/multicast/UDP and bounded NHC extension decoding. Prefixes come from scope-local 6CO Router Advertisements with link-local source, hop limit 255 and verified ICMPv6 checksum. At most 4,096 contexts share the 8-MiB credit budget; advertised lifetime and 65,536-ingress expiry apply. Missing, conflicting, expired and future contexts are not applied |
| UDP checksum elision | `internal/lowpan` restores checksums only with independently verified additional integrity. MS/TP CRC alone is not treated as upper-layer authorization; otherwise the packet remains qualified instead of being fabricated |
| ROHC | RDT supplies per-PLP CID configuration. CRC8 validates IR/IR-DYN; CRC3/CRC7 validate compressed headers before context updates. Explicit PLP metadata is required. Description/context changes and late packets are qualified; each channel reserves 64 KiB plus its table bytes against the shared budget |
| MPEG-TS | At most 256 PID states, 64 scopes, 512 retained stream entries/scope, 1,024 PAT programs, 128 source references per partial header and 8-KiB elementary prefixes. Scrambling, errors and discontinuities reset pending parsing. H.264/H.265 fixtures were generated from independent FFmpeg encoders (`TestSPSMetadataMatchesEncoderFixtures`) |
| Bluetooth | At most 128 pending ACL streams, 256 fragments and 65,539 reassembled bytes; fragments require a captured direction. Fixed ATT CID 4 is bounded to MTU 517. Standard signalling fields and pairing capabilities are metadata; signed ATT remains explicitly unverified |
| Provenance | Compression-context and AX.25 negotiation dependencies are identified by `LinkSourceRange.Purpose`; they do not inflate observed packet counts/timestamps. TS sources distinguish decoded ALP children from offsets into original capture packets |

## Explicit device profiles

`net capture -link-profiles profiles.json` selects profiles by logical interface,
link type, bus, address and endpoint. The file is capped at 64 KiB/64 rules;
unknown or duplicate selectors fail initialization. `NC_LINK_PROFILES` is the
equivalent startup setting, inherited by subsequent service analyses. The profile
file SHA-256 accompanies selected-profile metadata.

```json
{"Profiles":[
  {"Interface":0,"LinkType":209,"Bus":1,"Address":80,"Profile":"i2c-eeprom16"},
  {"Interface":0,"LinkType":266,"Bus":26,"Address":7,"Endpoint":1,"Profile":"usb-hid-boot-keyboard"},
  {"Interface":0,"LinkType":300,"Address":8,"Profile":"mdb-coin-changer"}
]}
```

Other supported names are `i2c-eeprom8`, `usb-hid-boot-mouse` and
`mdb-bill-validator` (address 48). USB descriptor metadata needs no profile file;
boot-report interpretation does. No EEPROM width, USB report layout or vendor
transaction format is inferred from a device address.

ALP lengths/counts follow [A/330:2026-04 §5.1](https://www.atsc.org/atsc-30-standard/a3302016-link-layer-protocol/):
the base length holds the 11 LSBs, and concatenation has `count + 1` component
lengths for `count + 2` packets. The preceding decoder got both rules wrong;
Wireshark's ALP parser is not an oracle for segmentation/concatenation reconstruction.

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
