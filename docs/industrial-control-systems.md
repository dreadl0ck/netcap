---
description: ICS / SCADA threat hunting
---

# Industrial Control Systems

## Protocol Support

Netcap offers audit records for the following protocols seen in industrial control systems:

* **S7comm / S7CommPlus** (Siemens S7-200/300/400/1200/1500, TPKT/COTP on TCP/102)
* **Modbus / ModbusTCP** (TCP/502)
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

```erlang
message Modbus {
    string Timestamp     = 1;
    int32  TransactionID = 2; // Identification of a MODBUS Request/Response transaction
    int32  ProtocolID    = 3; // It is used for intra-system multiplexing
    int32  Length        = 4; // Number of following bytes (includes 1 byte for UnitIdentifier + Modbus data length
    int32  UnitID        = 5; // Identification of a remote slave connected on a serial line or on other buses
    bytes  Payload       = 6;
    bool   Exception     = 7;
    int32  FunctionCode  = 8;

    PacketContext Context = 9;
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

