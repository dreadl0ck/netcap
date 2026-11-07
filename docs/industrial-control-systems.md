---
description: Passive industrial protocol evidence and its interpretation limits.
---

# Industrial Control Systems

## Protocol Support

| Record/protocol | Typical transport | Evidence boundary |
| --- | --- | --- |
| S7Comm / S7CommPlus | TPKT/COTP TCP/102 | Classic functions and visible Plus framing; not universal controller/model coverage |
| Modbus | TCP/502; explicitly configured RTU-over-TCP | Per-function requests/responses, correlation and loss markers |
| DNP3 | TCP/20000 | Link/application metadata, object headers and group-12 controls |
| CIP / ENIP | TCP/44818, UDP/2222 | Supported encapsulation/services; inspect selected record type |
| OPCUA | TCP/4840 | Supported visible framing/metadata; encryption limits payload interpretation |
| PROFINET | UDP/34964 | Supported CM/DCE-RPC structures |
| BACnet/IP | UDP/47808 | Supported service/object observations |
| IEC62351-related decoder | Registered TCP/2404 | Selected recognized formats; the name does not promise complete IEC 60870/MMS coverage |

Use `net capture -overview` for the installed inventory. A record type, a
well-known port and a full protocol implementation are different claims.

## Threat hunting

Collect both directions at an agreed observation point, preserve the original
capture and inspect health before interpreting negative results. Analyze a copy;
do not replay control messages to validate a passive finding.

| Workflow | Guide and rule pack |
| --- | --- |
| S7 functions, workstation baseline and response limits | [S7 hunt](s7-threat-hunt-AA26-231A.md); `internal/rules/examples/s7comm_hunt.yml` |
| Modbus writes, banks/ranges and diagnostics | [Modbus hunt](modbus-threat-hunting.md); `internal/rules/examples/modbus_hunt.yml` |
| DNP3 controls, SBO and point mapping | [DNP3 hunt](dnp3-threat-hunting.md); `internal/rules/examples/dnp3_hunt.yml` |

Site-dependent examples require the site's approved initiators, point/register
maps and maintenance policy. [Rules](RULES_ENGINE.md) and
[filtering](FILTERING.md) explain typed expressions and local-time helpers.

## Decoder selection off the standard port

The selector compares eligible parsers' evidence specificity; ascending
registered port order only breaks ties. A weak registered-port signature can
lose to stronger protocol evidence. Unknown-port UDP checks are datagram-aware;
MQTT-SN's ambiguous short signature is restricted to its registered ports.

DNP3 Secure Authentication can be selected by `dnp3` rather than `iec62351`
off-port because DNP3 validates its link CRC. Recognition does not establish
cryptographic verification of Secure Authentication. See [selector developer
references](internals.md#decoder-qualification) for the implementation and
confusable/reader regression tests.

## Record timing and direction

Readers map a message's first captured byte to its timestamp and observed
direction. Stream/transaction records can still be emitted only on completion
or flush. Packet timestamps, decoder emission order and transaction orientation
must not be treated as interchangeable; inspect each record's contract.

## S7comm

Classic protocol ID `0x32` exposes function/message/error fields. Ack-Data
`ErrorClass == 0 && ErrorCode == 0` is header status only. Inspect item results,
request/PDU reference and controller/process evidence before claiming success.
For responses the initiator is the destination, not the PLC source address.

Plus protocol ID `0x72` exposes supported framing/opcodes. The decoder sets
`PayloadObscured`; that is a visibility limitation, not proof that every version
uses the same encryption/integrity scheme. [The S7 guide](s7-threat-hunt-AA26-231A.md)
records released-rule limitations separately from source corrections.

## Modbus

The stream decoder distinguishes role, bank, zero-based wire address, quantity,
values, exceptions and matched/unmatched/ambiguous responses. RTU endpoints need
explicit `-modbus-rtu-endpoints`. Loss markers qualify missing coverage; a reply
does not identify a user or independently prove a process effect. Follow the
[field-level Modbus guide](modbus-threat-hunting.md).

## DNP3

Header/data CRCs qualify framing, not authenticated identity. Point indexes need
the outstation's device map. Group-12 control blocks are parsed; most other
values are stepped over, not interpreted. A successful control response is
distinct from independently observed equipment movement. See [DNP3 limits and
the v0.15.2 Class 0 correction](dnp3-threat-hunting.md#reconnaissance).

## CIP

This endpoint excerpt matches the released
[`CIP` schema](https://github.com/dreadl0ck/netcap/blob/v0.15.2/types/netcap.proto).
It is not a complete message definition:

```proto
message CIP {
  string SrcIP = 9;
  string DstIP = 10;
  int32 SrcPort = 11;
  int32 DstPort = 12;
  string CommunityID = 13;
}
```

## ENIP

The corresponding released endpoint fields are direct fields, not the obsolete
`PacketContext Context = 9` from older docs:

```proto
message ENIP {
  string SrcIP = 9;
  string DstIP = 10;
  int32 SrcPort = 11;
  int32 DstPort = 12;
}
```

Generate bindings from the tagged `types/netcap.proto`, never from partial
documentation excerpts. `make docs-check` verifies excerpt field numbers/types
against that schema.
