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

Shipped detection rules live in `rules/examples/`:

* `rules/examples/s7comm_hunt.yml` — S7comm function-code level hunt (AA26-231A)
* `rules/examples/modbus_hunt.yml` — Modbus request-level write/diagnostic/enumeration hunts
* `rules/examples/industrial_ports.yml` — port-based ICS exposure and scan rules

See the [Rules Engine](RULES_ENGINE.md) and [Filtering](FILTERING.md) guides for
the expression language and the ICS-relevant helper functions
(`IsApprovedWorkstation`, `IsBusinessHours`, `HourOfDay`, `Weekday`).

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
`S7PlusOpcodeName`. See `message S7Comm` in `netcap.proto` for the full schema.

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

See [Modbus Threat Hunting](modbus-threat-hunting.md) for the capture workflow,
the write/diagnostic/enumeration hunts, `rules/examples/modbus_hunt.yml`, RTU
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

