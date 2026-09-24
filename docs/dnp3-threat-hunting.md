---
description: DNP3 / IEEE 1815 threat hunting
---

# DNP3 Threat Hunting

Netcap decodes DNP3 (IEEE 1815) into structured audit records: link addresses,
link and application function codes, internal indications, object headers with
qualifier-driven ranges, decoded Control Relay Output Blocks,
Select-Before-Operate correlation, request/response correlation, and explicit
markers for data it could not decode. Use it for passive inventory and
hypothesis-driven triage, then validate candidates against the original capture
and the outstation's device profile. **A matching record is not proof of an
unauthorized command or a process change.**

```bash
net capture -read substation.pcap -out dnp3-hunt -include DNP3 \
  -reassemble-connections=true -payload -compress=true -http ""
net dump -read dnp3-hunt/DNP3.ncap.gz -json
net dump -read dnp3-hunt/DNP3.ncap.gz -fields     # exact field list for this build
```

`DNP3` is the TCP stream decoder and the audit-record name. TCP/20000 is
conventional, not required: a conversation is claimed when a link header whose
**CRC passes** is found, so nonstandard ports are covered and payload bytes that
happen to contain `0x05 0x64` are not. The cost is that a capture beginning
midstream, where no frame boundary falls inside the inspected bytes, is not
claimed. Detection is not a completeness guarantee; no records does not prove no
DNP3 activity.

## Why the protocol offers nothing to authenticate against

Base DNP3 is cleartext and unauthenticated. Select-Before-Operate is an
interlock against a mis-click, not an authorization step, and the same standard
ships Direct Operate, which skips it. A control from an address the network
accepts is the protocol working as specified, so every detection here starts
from behaviour and identity, not from a vulnerability.

Two identities matter and nothing on the wire binds them:

- **The IP**, in `SrcIP` / `DstIP`.
- **The DNP3 link address**, in `Source` / `Destination`.

A rule written on IP alone is watching half the wire. `DirectionMismatch`
reports the two disagreeing about direction; see
`DNP3 Control From Unapproved Master` in the shipped rules for checking both.

## Capture safely

1. Agree scope with OT operations: approved hosts, outstations, maintenance
   windows, capture duration and evidence handling.
2. Collect both directions from an approved TAP/SPAN point, without probing,
   replaying traffic or issuing test controls. Preserve the original PCAP,
   capture-point details, clock reference and packet-loss statistics.
3. Analyze a copy offline. Decoded values and payloads expose process data.

**Never issue a DNP3 function to validate a finding on production equipment.**
An Operate on a live outstation is not a finding, it is a breaker.

## Field reference

| Field(s) | Meaning and limit |
| --- | --- |
| `Timestamp` | Integer Unix nanoseconds, from the packet carrying the frame's first byte. Not the conversation's start. |
| `SrcIP`, `DstIP`, `SrcPort`, `DstPort`, `CommunityID` | Endpoints and flow ID, per direction. A response carries the outstation as `SrcIP`. Not authenticated identities. |
| `ParseStatus`, `ParseError` | `valid`, `malformed` (with a reason), `unsupported`, or `lost` on a capture-loss marker. A malformed record carries framing metadata only. |
| `LostBytes` | Only on `lost` markers: `> 0` is the gap reassembly reported, `-1` means unknown, `0` means framing rather than the capture became unusable. |
| `Length`, `Control` | Raw link header fields. `Length` counts control, addresses and user data, excluding every CRC. |
| `IsMaster`, `IsRequest` | The Control field's DIR and PRM bits. What the frame *claims*, not what the network observed. |
| `DirectionMismatch` | DIR disagrees with the observed direction. Set only when a TCP handshake fixed which end is the outstation. |
| `LinkFunctionCode`, `LinkFunctionCodeName` | Low nibble of Control. The name depends on PRM: `0x0` is `RESET_LINK_STATES` from a master and `ACK` from an outstation. |
| `LinkFCB`, `LinkFCV`, `LinkDFC` | Frame count bit; frame count valid on primary frames; data flow control (outstation buffer full) on secondary frames. |
| `Source`, `Destination` | 16-bit link addresses. A second identity, independent of the IP. |
| `IsBroadcast`, `IsSelfAddress` | Destination `0xFFFD`-`0xFFFF`, and `0xFFFC`. A broadcast control reaches every outstation on the link. |
| `TransportSeq`, `TransportFIN`, `TransportFIR` | Transport header. |
| `ApplicationSeq`, `ConfirmRequired`, `Unsolicited` | Application control. `ApplicationSeq` is **four bits**, so it repeats every sixteen requests. |
| `FunctionCode`, `FunctionCodeName` | IEEE 1815 Table 4-1, including 31 `ACTIVATE_CONFIG` and the Secure Authentication codes 32/33/131. |
| `IsCriticalFunction` | Operates the process or the device's availability: 4-14, 16-18, 31. Not `SELECT`, which arms rather than operates. |
| `IsConfigChange` | Alters what the outstation is: 2, 19-22 and the file set 25-31. |
| `IsAuthentication` | Secure Authentication v5 (32/33/131). **Not** FC29, which authenticates a file transfer. |
| `InternalIndications` and the 14 `IIN*` flags | Full 16-bit IIN on responses. Zeek's `iin` column is the second octet only, so a Zeek value of `4` is `0x0400` here. |
| `HeaderCRCValid`, `BlockCRCValid` | A record only exists if the header CRC passed, so the first is always true on a decoded record. `BlockCRCValid` false means the user data was corrupt and no values were decoded. |
| `Objects` | Object headers with `ObjectGroup`, `Variation`, `ObjectName`, `Qualifier`, `PrefixCode`, `RangeSpecifier`, `StartIndex`, `StopIndex`, `Count` (`-1` for "all objects"), and `ControlBlocks`. |
| `ObjectsTruncated` | Parsing stopped before the end of the fragment, so `Objects` is a prefix of what was sent. |
| `CorrelationStatus`, `RequestTimestamp`, `ResponseLatency` | `matched`, `unmatched`, `ambiguous` or `not_applicable` on responses. The last two are set only on a matched response. |
| `SBOStatus`, `SelectTimestamp`, `OperateLatency` | See [Select-Before-Operate](#select-before-operate). |

`DNP3CROB` carries `Index`, `PointName`, `ControlCode`, `ControlCodeName`,
`TripCloseCode` (0 NUL, 1 CLOSE, 2 TRIP), `OperationType`, `Clear`, `Queue`,
`Count`, `OnTime`, `OffTime` and `StatusCode`.

## The point index is not an address

Group 12 index 7 is a particular feeder only because that outstation's device
profile says so, and two vendors do not share a map. **A capture alone tells you
a breaker moved; it never tells you which breaker.**

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

The outstation is the **DNP3 link address**, not an IP: one address can be
reached over several paths, and one IP can front several outstations. Matched
points appear in `ControlBlocks[].PointName`; unmapped points leave it empty. An
unparseable file fails decoder initialisation rather than silently leaving every
point unnamed. `net export` takes the same flag; both read `NC_DNP3_POINT_MAP`.

## The primary hunt: the control plane

Read, Response and Unsolicited Response are almost all of a healthy network,
because telemetry is polling and polling is boring. Everything left over is the
control plane, and on most utility networks a month of it is short enough to
read by eye and put a work order against every line.

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "valid" && !(FunctionCode in [0, 1, 129, 130])'
```

`CONFIRM` (0) is excluded with the telemetry codes because it is
application-layer housekeeping for those same responses; drop the `0` to see it.

**If the result is too long to read, that is the finding**, and working out why
the control plane is that noisy comes before detection engineering.

Three things make a line a finding on the spot:

```bash
# Direct Operate, where the engineering standard says Select-Before-Operate
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "valid" && FunctionCode in [5, 6]'

# Disable Unsolicited, which silences the outstation's own event stream
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "valid" && FunctionCode == 21'

# A control whose source is not a master you can name, on BOTH identities
net dump -read dnp3-hunt/DNP3.ncap.gz -json -filter '
ParseStatus == "valid" && IsCriticalFunction &&
!((SrcIP == "192.0.2.10" && Source == 4) || (SrcIP == "192.0.2.11" && Source == 5))'
```

## Select-Before-Operate

Selects are paired with Operates within the master's own direction, per
outstation link address. `SBOStatus` is one of:

| Value | Meaning |
| --- | --- |
| `matched` | The Operate named what the Select armed, in sequence and in time. |
| `operate_without_select` | A control with no interlock in front of it. |
| `select_never_operated` | A Select no Operate followed. Routine on an operator cancel. |
| `sbo_object_mismatch` | The Operate named different points or control codes than the Select armed. |
| `sbo_sequence_mismatch` | Objects agree, but the application sequence number is not the Select's plus one. |
| `select_expired` | More than ten seconds apart, so the outstation had already discarded the Select. |

A matched Operate is an **attempt**. Pair it with the response before claiming
effect; the reply's `StatusCode` in `ControlBlocks` is the outstation's own
verdict:

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'CorrelationStatus == "matched" && FunctionCodeName == "RESPONSE"'
```

Response correlation keys on the application sequence number with the link
addresses reversed. That number is four bits, so two requests outstanding on the
same value make the reply `ambiguous` rather than guessing.

## Trip or close

The intent is two bits of one octet, and it is the difference between
energising and de-energising:

```bash
# Trip
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "valid" && any(Objects, {any(.ControlBlocks, {.TripCloseCode == 2})})'

# Close
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "valid" && any(Objects, {any(.ControlBlocks, {.TripCloseCode == 1})})'
```

## Reconnaissance

A Class 0 integrity poll returns the outstation's entire static point map for
four bytes on the wire, and is byte-identical to what the real master sends
every few minutes. One poll is routine; polling the estate in one window is an
inventory, so breadth is the signal:

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json -filter '
ParseStatus == "valid" && FunctionCode == 1 &&
any(Objects, {.ObjectGroup == 60 && .Variation == 0})'
```

The shipped rules express this with `distinct_field: Destination` over a
five-minute window. Cardinality carries no ordering, so it detects breadth, not
a scan pattern.

The outstation's own rejections are the other half, and the DNP3 analogue of a
Modbus exception code:

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json -filter '
ParseStatus == "valid" && (IINNoFuncCodeSupport || IINObjectUnknown || IINParameterError)'
```

## The trust that runs upward

The outstation is a trusted input to the master's parser, and it sits at the
least supervised point on the network: a cabinet with a padlock, two site visits
a year, over a link the utility frequently does not own. Unsolicited responses
mean it initiates. A malformed frame from that direction is the shape of the
problem, and it is now a record rather than a silent drop:

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json \
  -filter 'ParseStatus == "malformed" && !IsMaster'
```

Every such record has a **passing header CRC**, so it came from something
speaking DNP3 rather than from line noise. `ParseError` names the cause:
`length below minimum`, `block CRC failed`, `truncated transport header`,
`truncated application header` or `truncated internal indications`.

Ask which of your masters has ever been fuzzed, by anyone, and which published
advisories apply to the outstation firmware revision actually in service.

## Capture loss

A direction that stops producing evidence emits **exactly one** marker per loss
event: `ParseStatus == "lost"`, `CorrelationStatus == "not_applicable"`,
`LostBytes` as described above, and the direction's endpoints and last-seen
timestamp. No function code or object is set. `ParseError` names the cause —
`capture gap`, `unusable fragment`, `unframed bytes discarded` or
`truncated frame`.

```bash
net dump -read dnp3-hunt/DNP3.ncap.gz -json -filter 'ParseStatus == "lost"'
```

**An empty hunt result over a conversation that also produced loss markers is
not evidence of absence.** Check for markers on the endpoints and time range in
question before reporting a negative finding. A capture that began without a SYN
produces one `capture gap` marker per direction with `LostBytes == -1`.

## Running the shipped rules

`internal/rules/examples/dnp3_hunt.yml` contains the hunts above plus
availability and visibility triage. Two rules ship **disabled** because they
carry documentation addresses and placeholder hours — `DNP3 Control Outside
Maintenance Window` and `DNP3 Control From Unapproved Master`. Replace the
values before enabling. No rule configures a response action.

```bash
net capture -read substation.pcap -out dnp3-hunt -include DNP3 \
  -reassemble-connections=true -payload -http "" \
  -rules internal/rules/examples/dnp3_hunt.yml
net dump -read dnp3-hunt/Alert.ncap.gz -json
```

Keep `DNP3 Capture Loss` enabled: it is coverage evidence, not an attack signal,
and it is what separates a quiet network from a blind one.

## Output semantics

`net dump -json` emits integer nanosecond timestamps. The Elasticsearch-oriented
`DNP3.JSON()` method converts `Timestamp` — but not `RequestTimestamp`,
`SelectTimestamp`, `OperateLatency` or `ResponseLatency` — to milliseconds. CSV
renders `Objects` as a JSON cell. `-select` is CSV/table projection, not JSON
redaction.

Numeric encoding is not an evidence export: strings and repeated fields are
hashed and normalized, with no dictionary, so collisions are intentional. Use
CSV, JSON or protobuf when exact values are required.

The `nc_dnp3` Prometheus counter carries `FunctionCodeName` and `ParseStatus`
only. Endpoints, link addresses and object detail are deliberately not labels:
one series per address pair over a long capture is a cardinality explosion, and
these count observed frames, not executed commands.

## Limitations

- **No user identity.** Base DNP3 has no authentication; records attribute to
  endpoints and link addresses only. An IP allowlist expresses expected
  equipment, not who authorized an operation. Use workstation, access and change
  logs for attribution.
- **The index is not an address.** Without `-dnp3-point-map` or the device
  profile alongside the capture, a control identifies a point number and not a
  plant item.
- **Gaps end coverage, they do not repair it.** A `lost` marker says decoding
  stopped or resynchronised; everything up to the next decoded record is
  unobserved.
- **Batch, not real time.** Stream records and their alerts appear at connection
  completion or flush, not when a command arrives.
- **Direction needs a handshake.** Without an observed SYN the client and server
  assignment may be reversed, so `DirectionMismatch` is not evaluated.
- **Unmodelled objects stop the walk.** A group and variation with no known
  encoded size cannot be stepped over, so parsing stops and `ObjectsTruncated`
  is set. The unsizable header itself is **not** reported, because at that point
  its bytes are as likely to be the previous object's values.
- **Encrypted transport** (Secure Authentication aggressive mode aside, or DNP3
  over TLS) requires authorized plaintext evidence elsewhere.

## Remaining gaps

- No DNP3 over UDP, and no native serial capture. Only TCP is framed, though the
  link framing is identical over both.
- Object **values** are not decoded. Group 12 control blocks are parsed in full;
  every other group is framed and stepped over, not interpreted, so analog and
  binary point values are not in the records.
- Secure Authentication v5 is flagged by function code and group 120 is named,
  but challenge, reply and key-status contents are not parsed, so an
  authentication failure is not distinguished from a success.
- File transfer (group 70) is flagged by function code; file names and contents
  are not extracted.
- Select-Before-Operate correlation is per conversation. A Select and an Operate
  split across two TCP connections do not pair.

See [Filtering](FILTERING.md) for expression syntax and
[Industrial Control Systems](industrial-control-systems.md) for other protocols.
