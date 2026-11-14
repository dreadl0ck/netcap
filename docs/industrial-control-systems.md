---
description: Which industrial protocols Netcap decodes, and how to hunt in them.
---

# Industrial control systems

## Protocol Support

| Record/protocol          | Typical transport                           | Coverage                                                             |
| ------------------------ | ------------------------------------------- | -------------------------------------------------------------------- |
| S7Comm / S7CommPlus      | TPKT/COTP TCP/102                           | Classic S7 functions; S7CommPlus framing only. Not every PLC model.  |
| Modbus                   | TCP/502; RTU-over-TCP on endpoints you list | Per-function requests and responses, correlation, loss markers       |
| DNP3                     | TCP/20000                                   | Link and application metadata, object headers, group 12 controls     |
| CIP / ENIP               | TCP/44818, UDP/2222                         | Supported encapsulation and services; check the record type          |
| OPCUA                    | TCP/4840                                    | Visible framing and metadata; encrypted payloads are unreadable      |
| PROFINET                 | UDP/34964                                   | CM and DCE-RPC structures                                            |
| BACnet/IP                | UDP/47808                                   | Service and object observations                                      |
| IEC62351-related decoder | Registered TCP/2404                         | Selected recognized formats. Does not cover all of IEC 60870 or MMS. |

Run `net capture -overview` to list the decoders and fields in your build.

## Threat hunting

Capture both directions at an agreed TAP or SPAN port and keep the original capture. Check for capture loss before you trust an empty result. Analyze a copy, and never replay control messages to confirm a finding.

A typical hunt starts with a capture from a plant network, for example `plc-network.pcap`: an HMI polls a PLC and writes a few setpoints, and you look for any other host sending writes, restarts or CPU stops. Each guide below follows one such workflow for its protocol.

| Workflow                                                         | Guide and rule pack                                                                |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| S7 functions, workstation baseline, CPU stop and download        | [S7 hunt](s7-threat-hunt-AA26-231A.md); `internal/rules/examples/s7comm_hunt.yml`  |
| Modbus writes, register ranges and diagnostics                   | [Modbus hunt](modbus-threat-hunting.md); `internal/rules/examples/modbus_hunt.yml` |
| DNP3 controls, restarts, select-before-operate and point mapping | [DNP3 hunt](dnp3-threat-hunting.md); `internal/rules/examples/dnp3_hunt.yml`       |

Some rules need your approved initiators, register or point maps and maintenance windows before they are useful. [Rules](RULES_ENGINE.md) and [filtering](FILTERING.md) cover typed expressions and the local-time helpers.

### Practice captures

The Wireshark sample captures wiki (https://wiki.wireshark.org/SampleCaptures) lists Modbus/TCP, DNP3 and S7comm captures. The ICS-pcap collection by automayt on GitHub and the 4SICS ICS lab captures published by Netresec also contain industrial traffic. Run the guides against these before you use a production capture.

## Decoder selection off the standard port

Netcap decodes industrial protocols by content, so they are found on non-standard ports. When more than one decoder could match a stream, the one with the more specific evidence wins, and registered port order only breaks ties. Short, weak signatures therefore do not hide stronger ones. For UDP on unknown ports, MQTT-SN is only tried on its registered ports.

Off the standard port, DNP3 Secure Authentication traffic is decoded as `dnp3` rather than `iec62351`, because DNP3 validates its link CRC. Netcap recognizes the traffic and does not verify the authentication.

## Record timing and direction

A record's timestamp is the first captured byte of the message, and its direction comes from the stream. Stream and transaction records can be written only when the connection completes or flushes, so record order can differ from packet order. Check each record type's field reference before you sort or join on time.

## S7comm

Classic S7 (protocol ID `0x32`) exposes function, message and error fields. An Ack-Data with `ErrorClass == 0 && ErrorCode == 0` only means the header reports no error. Check the item results and the request/PDU reference before you report success. In response records the initiator is the destination (`DstIP`), not the PLC source address.

S7CommPlus (protocol ID `0x72`) exposes framing and opcodes. Netcap sets `PayloadObscured` because it cannot read the body. See [the S7 guide](s7-threat-hunt-AA26-231A.md).

## Modbus

The stream decoder reports role, bank, zero-based wire address, quantity, values, exceptions, and whether each response is matched, unmatched or ambiguous. RTU endpoints need `-modbus-rtu-endpoints`. Loss markers show where coverage is missing. A reply identifies neither a user nor a process change. See the [Modbus guide](modbus-threat-hunting.md).

## DNP3

The header and data CRCs validate framing, not identity. Point indexes mean something only with the outstation's device map. Netcap parses group 12 control blocks and steps over other object values without decoding them. See the [DNP3 guide](dnp3-threat-hunting.md#reconnaissance).

## CIP

The endpoint fields of the `CIP` record in [`types/netcap.proto`](https://github.com/dreadl0ck/netcap/blob/master/types/netcap.proto) are:

```proto
message CIP {
  string SrcIP = 9;
  string DstIP = 10;
  int32 SrcPort = 11;
  int32 DstPort = 12;
  string CommunityID = 13;
}
```

This is an excerpt, not the full message.

## ENIP

The `ENIP` endpoint fields:

```proto
message ENIP {
  string SrcIP = 9;
  string DstIP = 10;
  int32 SrcPort = 11;
  int32 DstPort = 12;
}
```

Generate bindings from `types/netcap.proto` itself, not from these excerpts.
