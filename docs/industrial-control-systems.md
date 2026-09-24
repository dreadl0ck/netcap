---
description: ICS / SCADA threat hunting
---

# Industrial Control Systems

## Protocol Support

Netcap offers audit records for the following protocols seen in industrial control systems:

* **S7comm / S7CommPlus** (Siemens S7-200/300/400/1200/1500, TPKT/COTP on TCP/102)
* **Modbus / ModbusTCP** (TCP/502, plus opt-in RTU-over-TCP)
* **DNP3** (TCP/20000)
* **EtherNet/IP** and **CIP** — Common Industrial Protocol (TCP/44818, UDP/2222)
* **OPC-UA** (TCP/4840)
* **PROFINET** (UDP/34964)
* **BACnet/IP** (UDP/47808)
* **IEC 62351 / IEC 60870-5-104 / MMS** (TCP/2404)

The decoders are enabled by default and are selected by well-known port with a
signature-based fallback. Each produces a typed audit record (e.g. `S7Comm`,
`Modbus`, `DNP3`).

## Threat hunting

For a full, hypothesis-driven S7 PLC threat hunt mapped to **CISA Joint Advisory
AA26-231A** — including function-code detection of writes/downloads/uploads/
PLC-stop/restart, an approved-engineering-workstation baseline, source→distinct-
destination enumeration detection, off-hours and geographic anomalies, and an
honest accounting of what netcap cannot see — see the dedicated guide:

* [Siemens S7 Series PLC Threat Hunt (AA26-231A)](s7-threat-hunt-AA26-231A.md)
* [Modbus Threat Hunting](modbus-threat-hunting.md)
* [DNP3 Threat Hunting](dnp3-threat-hunting.md)

Shipped detection rules live in `internal/rules/examples/`:

* `internal/rules/examples/s7comm_hunt.yml` — S7comm function-code level hunt (AA26-231A)
* `internal/rules/examples/modbus_hunt.yml` — Modbus request-level write/diagnostic/enumeration hunts
* `internal/rules/examples/dnp3_hunt.yml` — DNP3 control-plane, Select-Before-Operate and visibility hunts
* `internal/rules/examples/industrial_ports.yml` — port-based ICS exposure and scan rules

See the [Rules Engine](RULES_ENGINE.md) and [Filtering](FILTERING.md) guides for
the expression language and the ICS-relevant helper functions
(`IsApprovedWorkstation`, `IsBusinessHours`, `HourOfDay`, `Weekday`).

## Decoder selection off the standard port

A conversation on a registered port goes to that port's decoder. Everything else
falls back to a scan of every decoder, and since 2026-09 that scan **asks them
all and keeps the one that required the most evidence**, with ascending port
order only as a tie-break. `SelectDecoder` in `internal/decoder/stream/selection.go`
is the single implementation for TCP and UDP; it previously existed twice, and
the copies had drifted.

It used to take the first decoder that said yes, walking ports upward. Port
number measures nothing, so a one-byte check on port 21 outranked a checksum on
port 20000 — and the ICS decoders sit high: modbus 502, cip 2222/44818, dnp3
20000, profinet 34964.

Each decoder declares a `Specificity` on the `core.Specificity*` scale —
heuristic, weak, structural, magic, validated — and four whose evidence varies
with the input supply a per-match `Confidence` instead. `decoder_matching_test.go`
runs one traffic sample per registered decoder through the real selector and
prints the result as a matrix.

| Decoder | Confidence varies because |
| --- | --- |
| `s7comm` | a data-transfer PDU with a validated S7 protocol id is structural; a bare TPKT/COTP header is weak, and every X.224 connection request matches it |
| `cip` | an ENIP command that encapsulates CIP is validated; List Services and the other header-only commands are weak, and a DCE/RPC header satisfies them |
| `socks` | a greeting the server answered with a method selection is structural; a client-side greeting alone is three bytes, which a DCE/RPC header also satisfies |
| `profinet` | PROFINET CM is DCE/RPC **version 4**; the decoder tolerates version 5 to stay usable mid-session, but version 5 on a dynamic port is far more likely to be Windows MSRPC |

Measured over one sample per decoder, this took the protocols that do not reach
their own decoder off their own port from **5 of 29 to 1**:

| Protocol | Was taken by | Now |
| --- | --- | --- |
| `SMTP` | `FTP` (21) — both match `"220 "`, and SMTP also requires `"SMTP"` | fixed by ranking |
| `SOCKS` | `DCERPC` (135) — `05 01 00` is a valid v5 header | fixed by confidence |
| `RDP` | `S7Comm` (102) | fixed by confidence |
| `PROFINET` | `CIP` (2222) | fixed by confidence |
| `QUICClientHello` | `Protobuf` — unreachable on any path | fixed by pass order |

QUIC was a different fault. It is in no port map, because UDP/443 belongs to TLS
over TCP, so it was reachable only through a `UDPStreamDecoders` pass that ran
*after* the whole scan — and protobuf accepts a QUIC Initial packet. Those
decoders now compete in the scan rather than following it.

On real traffic the change is small and checkable: replaying The Ultimate PCAP
moves exactly **one** of 359 conversations, an IPv6 session to port 587 that was
recorded as FTP and is SMTP submission, and makes 10 QUIC records visible that
were not produced at all.

**The one remaining, and it is accepted rather than open.** A DNP3 Secure
Authentication frame is claimed by `dnp3` (20000) rather than `iec62351` (2404)
off-port, because dnp3 validates a CRC-16 where iec62351 checks a function code.
dnp3 parses SA correctly — it flags functions 32/33/131 and names object group
120 — and on port 2404 iec62351 still wins, so traffic genuinely on the IEC
62351 port is unaffected.

`confusable_test.go` holds the cases where two decoders both have a claim —
MSRPC against PROFINET, an SMTP banner against FTP's, an X.224 connection
request against S7comm — each naming the rival and reporting the specificity
margin, so a contest decided by 0 is visible before it becomes a regression.

## Record timing and direction

A reader that concatenates `conversation.Data` into one buffer and stamps every
record with `FirstClientPacket` loses two things: the direction, so a response
carries the client's address and cannot be told from the command that provoked
it, and the time, so a connection held open for days collapses to one instant.

Both were fixed in `dnp3` and `modbus` and then found in eleven more readers by
`reader_hygiene_test.go`, which drives each decoder with a two-sided
conversation and reads `Timestamp` and `SrcIP` off whatever record type comes
back. Measured on The Ultimate PCAP, before and after:

| Decoder | Records | Timestamps | Source addresses |
| --- | --- | --- | --- |
| DCERPC | 368 → 368 | 27 → 368 | 3 → 4 |
| Kerberos | 135 → 135 | 67 → 135 | 4 → 6 |
| BGP | 283 → 283 | 20 → 209 | 8 → 14 |
| TACACS | 18 → 18 | 6 → 18 | 1 → 2 |
| Syslog | 12 → 12 | 4 → 12 | 4 → 4 |

No record count changes — nothing is gained or lost, the records that existed
now say when they happened and which way they went. BGP settles at 209 rather
than 283 because several BGP messages genuinely share a TCP segment.

`core.Flatten` returns a `FragmentIndex` alongside the concatenated bytes, so a
reader that needs the whole direction in one slice can still resolve a message's
offset back to the fragment it arrived in. That is what made converting the
merged readers a few lines each rather than a restructure apiece.

The line-oriented readers — `ftp`, `imap`, `irc` — go through
`streamutils.DecodeConversationAt`, which exposes a `ReadPosition` alongside the
`bufio.Reader`. The offset is exact rather than estimated: bytes handed to the
buffer, minus what the buffer still holds, minus what `bufio` has read ahead and
not yet returned. On the same capture, FTP goes from 7 distinct timestamps
across 142 records to 136, and IMAP from 5 across 163 to 59 — the remainder
being multi-line responses that genuinely share a packet.

**Known and still open:**

* `http` and `socks` attribute every record to the client, and that is right —
  both record types model a transaction, carrying request and reply fields in
  one record, rather than a single message. `socks` also timestamps from the
  conversation, which is correct for the same reason: its one record describes a
  negotiation that begins when the connection does.
* `iec62351`'s reader merges both directions and timestamps from the
  conversation, across all four of its protocol paths. The DNP3-SA framing
  defects are fixed; this one is a reader-wide restructure.
* `parseDNP3SAObject` re-assigns the message type names `getDNP3SAObjectName`
  has already produced, so the table exists twice.

Four signatures were tightened separately in 2026-09 because they were claiming
ICS traffic they could not parse. `TestFallbackShadowingIsRecorded` and
`TestDNP3SurvivesEveryOutstationAddress` pin that result.

| Decoder | Port | Was | Took |
| --- | --- | --- | --- |
| `kerberosaudit` | 88 | one ASN.1 tag byte at two offsets, both directions | DNP3 whose outstation address low byte was 106-109 or 126; ~2% of Modbus and CIP |
| `socks` | 1080 | `client[0]==0x05` and a method count compared against the whole direction | every DNP3 conversation of 102 bytes or more |
| `iec62351` | 2404 | any byte equal to `0x78` from offset 11 | essentially every DNP3 conversation |
| `irc` | 6667 | `"001"` as a bare substring anywhere in the server direction | any long binary conversation |

## S7comm

S7comm is the Siemens S7 Communication Protocol (S7-300/400 classic, `0x32`) and
S7CommPlus (S7-1200/1500 via TIA Portal, `0x72`), carried over TPKT (RFC 1006)
and ISO-COTP on TCP port 102. The decoder parses function codes (read/write,
block download/upload, PI services, PLC stop), UserData/SZL enumeration, and
Ack-Data error classes, and flags security-relevant and critical operations.

For S7CommPlus, the request/response body is protected by session-keyed
integrity material: netcap parses the cleartext framing (opcode) and sets
`PayloadObscured = true` when the function code cannot be determined — so the
blind spot is visible in output rather than silently missed.

Key `S7Comm` audit-record fields for hunting: `FunctionCode` / `FunctionName`,
`MessageType` (1=Job, 2=Ack, 3=Ack-Data, 7=UserData), `ErrorClass`
(`0` on an Ack-Data means the operation completed), `IsCriticalOperation`,
`IsSecurityRelevant`, `SubFunctionName` (names cold/warm/hot restart),
`UserDataFunctionGroup` / `UserDataSubFunction` (SZL enumeration), and the
S7CommPlus visibility fields `PayloadObscured` / `S7PlusOpcode` /
`S7PlusOpcodeName`. See `message S7Comm` in `types/netcap.proto` for the full schema.

## Modbus

The decoder parses the full PDU per function: request/response role, bank,
zero-based wire addresses, quantities and values, FC8 diagnostics, FC43 MEI14
device identification, FC20/21 file records, FC22 masks, the serial-oriented
FC7/11/12/17 and FC24 replies, and exception codes. It correlates requests with
responses inside a TCP connection and backfills a matched response's address
range from its request. Data the decoder could not frame is reported as a
`ParseStatus == "lost"` marker record carrying `LostBytes`, so coverage gaps are
visible instead of silent. MBAP detection is port-independent; RTU framing over
TCP is decoded only for endpoints named with `-modbus-rtu-endpoints`.

Modbus is decoded **only** as a stream decoder, deliberately. gopacket does
carry a Modbus layer (`layers.LayerTypeModbus`, id 153) which registers itself
on TCP/502, so a packet-layer decoder would compile and fire on exactly the
traffic the stream decoder already handles. It would write a second set of
`NC_Modbus` records filling 7 of the type's 51 fields -- no role, address,
values, correlation or loss marker -- duplicating every ADU with a record that
looks valid and answers nothing. A commented-out decoder claiming gopacket
lacked the layer was removed rather than enabled.

See [Modbus Threat Hunting](modbus-threat-hunting.md) for the capture workflow,
the write/diagnostic/enumeration hunts, `internal/rules/examples/modbus_hunt.yml`, RTU
configuration and the limitations.

```erlang
message Modbus {
    int64  Timestamp     = 1;
    int32  TransactionID = 2;
    int32  ProtocolID    = 3;
    int32  Length        = 4;
    int32  UnitID        = 5;   // unit behind an endpoint, not a user
    bytes  Payload       = 6;   // raw PDU only, with -payload
    bool   Exception     = 7;
    int32  FunctionCode  = 8;   // exception bit stripped

    string SrcIP = 9; string DstIP = 10; int32 SrcPort = 11; int32 DstPort = 12;
    string CommunityID = 13;

    string Transport   = 14;    // "tcp" | "rtu_tcp"
    string MessageRole = 15;    // "request" | "response" | "unknown"
    string ParseStatus = 16;    // "valid" | "malformed" | "unsupported" | "lost"
    string ParseError  = 17;
    string Bank        = 18;    // coils | discrete_inputs | holding_registers | input_registers | file_records

    bool   HasAddress = 19; uint32 Address = 20; uint32 Quantity = 21;
    repeated uint32 Values = 22;                          // FC1-6, 15, 16, 22; FC23 response reads;
                                                          // FC7/11/12 status words and FC24 queue
    bool   HasReadAddress  = 23; uint32 ReadAddress  = 24; uint32 ReadQuantity  = 25;
    bool   HasWriteAddress = 26; uint32 WriteAddress = 27; uint32 WriteQuantity = 28;
    repeated uint32 WriteValues = 29;                     // FC23 only

    uint32 ExceptionCode = 30;
    bool   HasDiagnostic = 31; uint32 DiagnosticSubfunction = 32; bytes DiagnosticData = 33;
    uint32 MEIType = 34; uint32 ReadDeviceIDCode = 35;
    repeated ModbusDeviceIDObject DeviceIDObjects = 36;
    repeated ModbusFileRecord     FileRecords     = 37;
    uint32 AndMask = 38; uint32 OrMask = 39;              // FC22

    string CorrelationStatus = 40;  // matched | unmatched | ambiguous | not_applicable
    int64  RequestTimestamp  = 41;  // matched responses only
    int64  ResponseLatency   = 42;  // nanoseconds, matched responses only

    uint32 DeviceIDObjectID = 43; uint32 DeviceIDConformityLevel = 44;
    bool   DeviceIDMoreFollows = 45; uint32 DeviceIDNextObjectID = 46;

    bool   HasMBAP = 47;            // MBAP header present
    bool   HasChecksum = 48; bool ChecksumValid = 49;     // RTU CRC16
    bool   Broadcast = 50;          // RTU unit-zero write, no response expected

    int64  LostBytes = 51;          // ParseStatus "lost" markers only: gap size,
                                    // -1 unknown extent, 0 framing became unusable
}

message ModbusDeviceIDObject { uint32 ID = 1; bytes Value = 2; }
message ModbusFileRecord {
    uint32 ReferenceType = 1; uint32 FileNumber = 2; uint32 RecordNumber = 3;
    uint32 RecordLength  = 4; repeated uint32 Values = 5;
}
```

## DNP3

The decoder frames each direction independently and validates the IEEE 1815
link header CRC and every data-block CRC, so a conversation is claimed on a
16-bit check rather than on the two start bytes, and `0x05 0x64` inside a
payload is not reported as a frame. Each frame is timestamped from the packet
carrying its first byte, which matters because a master holds a connection open
for days.

It decodes the link layer (function code, FCB/FCV/DFC, broadcast and
self-address detection), the transport and application headers, all fourteen
internal indications, and object headers with full qualifier handling —
per-object index or size prefixes and every range form. Object values are
stepped over using the group and variation's encoded size, so a header is never
read out of the previous object's data. Group 12 Control Relay Output Blocks are
parsed in full, including the trip/close code that distinguishes opening a
breaker from closing it.

Selects are correlated with Operates per outstation (`SBOStatus`), and responses
with requests on the application sequence number (`CorrelationStatus`). Frames
that framed but did not parse are reported as `ParseStatus == "malformed"` with
a reason and a passing header CRC, which is what makes a malformed frame *from
an outstation* a queryable event. Data that could not be framed becomes a
`ParseStatus == "lost"` marker carrying `LostBytes`.

`-dnp3-point-map` resolves point indexes against a device profile
(`outstation,group,index,name`), keyed on the DNP3 link address rather than the
IP. Without it a capture shows that a control was issued but not which plant
item it addressed.

See [DNP3 Threat Hunting](dnp3-threat-hunting.md) for the capture workflow, the
control-plane and Select-Before-Operate hunts,
`internal/rules/examples/dnp3_hunt.yml`, the point map and the limitations.

## CIP

```erlang
message CIP {
    string          Timestamp        = 1;
    bool            Response         = 2; // false if request, true if response
    int32           ServiceID        = 3; // The service specified for the request
    uint32          ClassID          = 4; // request only
    uint32          InstanceID       = 5; // request only
    int32           Status           = 6; // Response only
    repeated uint32 AdditionalStatus = 7; // Response only
    bytes           Data             = 8; // Command data for request, reply data for response
    PacketContext   Context          = 9;
}
```

## ENIP

```erlang
message ENIP {
    string                  Timestamp        = 1;
    uint32                  Command          = 2; 
    uint32                  Length           = 3;
    uint32                  SessionHandle    = 4;
    uint32                  Status           = 5;
    bytes                   SenderContext    = 6;
    uint32                  Options          = 7;
    ENIPCommandSpecificData CommandSpecific  = 8;
    PacketContext           Context          = 9;
}
```

