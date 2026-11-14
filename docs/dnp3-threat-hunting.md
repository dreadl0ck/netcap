---
description: >-
  Hunting for unauthorized controls, restarts and recon in DNP3 (IEEE 1815)
  captures.
---

# DNP3 threat hunting

Netcap decodes DNP3 (IEEE 1815) into audit records: link addresses, link and application function codes, internal indications, object headers with qualifier-driven ranges, decoded Control Relay Output Blocks (CROBs), Select-Before-Operate correlation, request/response correlation, and markers for data it could not decode. Use them to inventory DNP3 traffic and to triage hypotheses, then check each candidate against the original capture and the outstation's device profile.

A typical case: `substation.pcap` holds traffic between a SCADA master (10.0.0.5, link address 4) and several RTUs. You want to know whether anything other than that master sends controls or restarts, whether any control skipped Select-Before-Operate, and whether an outstation sends frames it should not.

```bash
net capture -read substation.pcap -out dnp3-hunt -include DNP3 \
  -reassemble-connections=true -payload -compress=true -http ""
net dump -read dnp3-hunt/DNP3.ncap.gz -json
net dump -read dnp3-hunt/DNP3.ncap.gz -fields     # exact field list for this build
```

`DNP3` is both the TCP stream decoder and the audit-record name. TCP/20000 is only the convention. Netcap claims a conversation when it finds a link header whose CRC passes, so DNP3 on other ports is detected, and payload bytes that happen to contain `0x05 0x64` are not mistaken for it. A capture that starts midstream, with no frame boundary in the inspected bytes, is not claimed. Off the standard port, DNP3 Secure Authentication traffic is decoded as `dnp3` rather than `iec62351`; see [decoder selection](industrial-control-systems.md#decoder-selection-off-the-standard-port).

## Why the protocol offers nothing to authenticate against

Base DNP3 is cleartext and has no authentication. Select-Before-Operate protects against an operator's mis-click and is not an authorization step, and the standard also defines Direct Operate, which skips it. A control from an address the network accepts is valid protocol traffic, so every detection here starts from behaviour and sender identity.

Two identities matter, and nothing on the wire binds them:

* **The IP**, in `SrcIP` / `DstIP`.
* **The DNP3 link address**, in `Source` / `Destination`.

A rule on the IP alone watches half the wire. `DirectionMismatch` reports when the two disagree about direction. The shipped rule `DNP3 Control From Unapproved Master` checks both.

An IP allowlist says which equipment you expect, not who authorized an operation. Use workstation, access and change logs for attribution.

## Capture safely

1. Agree scope with OT operations: approved hosts, outstations, maintenance windows, capture duration and evidence handling.
2. Collect both directions from an approved TAP or SPAN port. Do not probe, replay traffic or send test controls. Keep the original PCAP, the capture-point details, the clock reference and the packet-loss statistics.
3. Analyze a copy offline. Decoded values and payloads expose process data.

Never send a DNP3 function to production equipment to validate a finding. An Operate on a live outstation is not a test; it can open a breaker.

## Field reference

| Field(s)                                                   | Meaning                                                                                                                                                                                      |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Timestamp`                                                | Integer Unix nanoseconds, from the packet carrying the frame's first byte (not the conversation's start).                                                                                    |
| `SrcIP`, `DstIP`, `SrcPort`, `DstPort`, `CommunityID`      | Endpoints and flow ID, per direction. A response carries the outstation as `SrcIP`. These are addresses, not authenticated identities.                                                       |
| `ParseStatus`, `ParseError`                                | `valid`, `malformed` (with a reason), `unsupported`, or `lost` on a capture-loss marker. A malformed record carries framing metadata only.                                                   |
| `LostBytes`                                                | Only on `lost` markers: `> 0` is the gap reassembly reported, `-1` means unknown, `0` means framing rather than the capture became unusable.                                                 |
| `Length`, `Control`                                        | Raw link header fields. `Length` counts control, addresses and user data, excluding every CRC.                                                                                               |
| `IsMaster`, `IsRequest`                                    | The Control field's DIR and PRM bits: what the frame claims, not what the network observed.                                                                                                  |
| `DirectionMismatch`                                        | DIR disagrees with the observed direction. Set only when a TCP handshake fixed which end is the outstation.                                                                                  |
| `LinkFunctionCode`, `LinkFunctionCodeName`                 | Low nibble of Control. The name depends on PRM: `0x0` is `RESET_LINK_STATES` from a master and `ACK` from an outstation.                                                                     |
| `LinkFCB`, `LinkFCV`, `LinkDFC`                            | Frame count bit; frame count valid on primary frames; data flow control (outstation buffer full) on secondary frames.                                                                        |
| `Source`, `Destination`                                    | 16-bit link addresses, a second identity independent of the IP.                                                                                                                              |
| `IsBroadcast`, `IsSelfAddress`                             | Destination `0xFFFD`-`0xFFFF`, and `0xFFFC`. A broadcast control reaches every outstation on the link.                                                                                       |
| `TransportSeq`, `TransportFIN`, `TransportFIR`             | Transport header.                                                                                                                                                                            |
| `ApplicationSeq`, `ConfirmRequired`, `Unsolicited`         | Application control. `ApplicationSeq` is four bits, so it repeats every sixteen requests.                                                                                                    |
| `FunctionCode`, `FunctionCodeName`                         | IEEE 1815 Table 4-1, including 31 `ACTIVATE_CONFIG` and the Secure Authentication codes 32/33/131.                                                                                           |
| `IsCriticalFunction`                                       | Operates the process or the device's availability: 4-14, 16-18, 31. Not `SELECT`, which arms but does not operate.                                                                           |
| `IsConfigChange`                                           | Alters what the outstation is: 2, 19-22 and the file set 25-31.                                                                                                                              |
| `IsAuthentication`                                         | Secure Authentication v5 (32/33/131). Not FC29, which authenticates a file transfer.                                                                                                         |
| `InternalIndications` and the 14 `IIN*` flags              | Full 16-bit IIN on responses. Zeek's `iin` column is the second octet only, so a Zeek value of `4` is `0x0400` here.                                                                         |
| `HeaderCRCValid`, `BlockCRCValid`                          | A record exists only if the header CRC passed, so the first is always true on a decoded record. `BlockCRCValid` false means the user data was corrupt and no values were decoded.            |
| `Objects`                                                  | Object headers with `ObjectGroup`, `Variation`, `ObjectName`, `Qualifier`, `PrefixCode`, `RangeSpecifier`, `StartIndex`, `StopIndex`, `Count` (`-1` for "all objects"), and `ControlBlocks`. |
| `ObjectsTruncated`                                         | Parsing stopped before the end of the fragment, so `Objects` is a prefix of what was sent.                                                                                                   |
| `CorrelationStatus`, `RequestTimestamp`, `ResponseLatency` | `matched`, `unmatched`, `ambiguous` or `not_applicable` on responses. The last two are set only on a matched response.                                                                       |
| `SBOStatus`, `SelectTimestamp`, `OperateLatency`           | See [Select-Before-Operate](dnp3-threat-hunting.md#select-before-operate).                                                                                                                   |

`DNP3CROB` carries `Index`, `PointName`, `ControlCode`, `ControlCodeName`, `TripCloseCode` (0 NUL, 1 CLOSE, 2 TRIP), `OperationType`, `Clear`, `Queue`, `Count`, `OnTime`, `OffTime` and `StatusCode`.

## The point index is not an address

Group 12 index 7 is a particular feeder only because that outstation's device profile says so, and vendors do not share a map. A captured control request does not show that a breaker moved. To interpret a point or status you need the outstation's point map and process evidence.

Keep the point list with the capture. `-dnp3-point-map` puts it in the evidence:

```bash
net capture -read substation.pcap -out dnp3-hunt -include DNP3 \
  -reassemble-connections=true -payload -dnp3-point-map points.csv -http ""
```

```csv
# outstation,group,index,name
3,12,7,Feeder 4 breaker
3,12,8,Feeder 5 breaker
```

The outstation is the DNP3 link address, not an IP: one address can be reached over several paths, and one IP can front several outstations. Matched points appear in `ControlBlocks[].PointName`, and unmapped points leave it empty. An unparseable file fails decoder initialisation. `net export` takes the same flag, and both read `NC_DNP3_POINT_MAP`.

## The primary hunt: the control plane

First separate routine telemetry and confirmation functions from everything else. Then compare the remaining controls, configuration, restart and file activity with the site's baseline and work orders.

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "valid" && !(FunctionCode in [0, 1, 129, 130])'
```

`CONFIRM` (0) is excluded along with the telemetry codes because it is housekeeping for those responses. Drop the `0` to see it.

Many hits usually come from maintenance, a long capture or duplicate observations, so account for those first. These queries pick out candidates to check against site policy:

```bash
# Direct Operate, where the site's standard calls for Select-Before-Operate
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "valid" && FunctionCode in [5, 6]'

# Cold (13) and warm (14) restart commands
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "valid" && FunctionCode in [13, 14]'

# Disable Unsolicited, which silences the outstation's own event reporting
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "valid" && FunctionCode == 21'

# A control from anything other than the two known masters, checked on BOTH identities
net dump -read dnp3-hunt/DNP3.ncap.gz -json -filter '
ParseStatus == "valid" && IsCriticalFunction &&
!((SrcIP == "10.0.0.5" && Source == 4) || (SrcIP == "10.0.0.6" && Source == 5))'
```

## Select-Before-Operate

Netcap pairs each Select with an Operate in the master's direction, per outstation link address. `SBOStatus` is one of:

| Value                    | Meaning                                                                                                          |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `matched`                | The Operate named what the Select armed, in sequence and in time.                                                |
| `operate_without_select` | A control with no Select in front of it.                                                                         |
| `select_never_operated`  | A Select that no Operate followed. Routine when an operator cancels.                                             |
| `sbo_object_mismatch`    | The Operate named different points or control codes than the Select armed.                                       |
| `sbo_sequence_mismatch`  | The objects agree, but the application sequence number is not the Select's plus one.                             |
| `select_expired`         | The Operate came after Netcap's ten-second correlation window. Check the outstation's configured select timeout. |

The outstation's reply carries its own verdict in `StatusCode` in `ControlBlocks`. Look at the response to see what happened to an Operate:

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'CorrelationStatus == "matched" && FunctionCodeName == "RESPONSE"'
```

Response correlation keys on the application sequence number with the link addresses reversed. The number is four bits, so when two requests are outstanding on the same value the reply is `ambiguous`.

## Trip or close

The intent is two bits of one octet, and it decides whether the point is energised or de-energised:

```bash
# Trip
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "valid" && any(Objects, {any(.ControlBlocks, {.TripCloseCode == 2})})'

# Close
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "valid" && any(Objects, {any(.ControlBlocks, {.TripCloseCode == 1})})'
```

## Reconnaissance

A Class 0 request uses group 60 variation 1 (see [opendnp3's group/variation definitions](https://github.com/dnp3/opendnp3/blob/master/cpp/lib/src/gen/GroupVariation.cpp)). It asks for static class data, not for the site's mapping of point indexes to equipment. Polling is routine, so use breadth and the approved baseline to find hosts that poll outstations they normally do not:

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json -filter '
ParseStatus == "valid" && FunctionCode == 1 &&
any(Objects, {.ObjectGroup == 60 && .Variation == 1})'
```

The shipped `DNP3 Class 0 Integrity Poll Sweep` rule counts distinct `Destination` values over 300 seconds, so it measures breadth, not order.

The outstation's rejections are the DNP3 counterpart of Modbus exception codes:

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json -filter '
ParseStatus == "valid" && (IINNoFuncCodeSupport || IINObjectUnknown || IINParameterError)'
```

## The trust that runs upward

Outstations sit in remote cabinets, often on links the utility does not own, and the master parses whatever they send, including unsolicited responses. A malformed frame from an outstation is recorded rather than dropped:

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "malformed" && !IsMaster'
```

`ParseError` names the cause: `length below minimum`, `block CRC failed`, `truncated transport header`, `truncated application header` or `truncated internal indications`. Check which published advisories apply to the outstation firmware revision in service.

Unsolicited responses show what an outstation reports on its own initiative. A burst of them, or a sudden stop after a Disable Unsolicited request, is worth a look:

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json -filter 'ParseStatus == "valid" && Unsolicited'
```

## Capture loss

When a direction stops producing evidence, Netcap writes exactly one marker per loss event: `ParseStatus == "lost"`, `CorrelationStatus == "not_applicable"`, `LostBytes` as above, and the direction's endpoints and last-seen timestamp. No function code or object is set. `ParseError` names the cause: `capture gap`, `unusable fragment`, `unframed bytes discarded` or `truncated frame`.

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json -filter 'ParseStatus == "lost"'
```

Check for markers on the endpoints and time range you care about before you report a negative result. A capture that begins without a SYN produces one `capture gap` marker per direction with `LostBytes == -1`.

## Running the shipped rules

`internal/rules/examples/dnp3_hunt.yml` contains the hunts above plus availability and visibility triage. Two rules ship disabled because they carry documentation addresses and placeholder hours: `DNP3 Control Outside Maintenance Window` and `DNP3 Control From Unapproved Master`. Replace the values before you enable them. No rule triggers a response action.

```bash
net capture -read substation.pcap -out dnp3-hunt -include DNP3 \
  -reassemble-connections=true -payload -http "" \
  -rules internal/rules/examples/dnp3_hunt.yml
net dump -read dnp3-hunt/Alert.ncap.gz -json
```

Keep `DNP3 Capture Loss` enabled. It does not signal an attack; it separates a quiet network from a blind one.

## Output semantics

`net dump -json` emits integer nanosecond timestamps. The Elasticsearch-oriented `DNP3.JSON()` method converts `Timestamp`, but not `RequestTimestamp`, `SelectTimestamp`, `OperateLatency` or `ResponseLatency`, to milliseconds. CSV renders `Objects` as a JSON cell. `-select` projects columns in CSV and table output; it does not redact JSON.

The numeric encoding is lossy: strings and repeated fields are hashed and normalized, with no dictionary, so collisions happen. Use CSV, JSON or protobuf when you need exact values.

The `nc_dnp3` Prometheus counter has only `FunctionCodeName` and `ParseStatus` labels. Endpoints, link addresses and object detail are not labels because one series per address pair would explode cardinality. The counter counts observed frames, not executed commands.

## Limitations

* **Gaps.** A `lost` marker says decoding stopped or resynchronised. Everything up to the next decoded record is unobserved.
* **Batch, not real time.** Stream records and their alerts appear when the connection completes or flushes, not when a command arrives.
* **Direction needs a handshake.** Without an observed SYN, the client and server roles may be reversed, so `DirectionMismatch` is not evaluated.
* **Unmodelled objects stop parsing.** A group and variation with no known encoded size cannot be stepped over, so parsing stops and `ObjectsTruncated` is set. The unsizable header itself is not reported, because its bytes are as likely to be the previous object's values.
* **Encrypted transport** (DNP3 over TLS, or Secure Authentication aggressive mode) needs plaintext evidence from elsewhere.

## Remaining gaps

* No DNP3 over UDP and no native serial capture. Only TCP is framed.
* Object values are not decoded. Group 12 control blocks are parsed in full, and every other group is framed and stepped over, so analog and binary point values are not in the records.
* Secure Authentication v5 is flagged by function code and group 120 is named, but challenge, reply and key-status contents are not parsed, so a failed authentication looks the same as a successful one.
* File transfer (group 70) is flagged by function code. File names and contents are not extracted.
* Select-Before-Operate correlation is per conversation. A Select and an Operate on two different TCP connections do not pair.

See [Filtering](FILTERING.md) for expression syntax and [Industrial Control Systems](industrial-control-systems.md) for other protocols.
