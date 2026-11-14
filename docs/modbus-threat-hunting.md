# Modbus threat hunting

Netcap decodes Modbus into audit records: request/response role, per-function addresses, quantities and values, diagnostics, device and server identification, file records, exception codes, request/response correlation, and markers for data it could not decode. Use them to inventory Modbus traffic and to triage hypotheses, then check each candidate against the original capture and the site's register map.

A typical case: in `plc-network.pcap`, an HMI at 192.168.1.20 polls a PLC at 192.168.1.10 and writes a few setpoint registers. You look for a host other than the HMI that sends write requests, and for the HMI writing outside its usual registers. The sections below build that hunt step by step.

## Capture Safely

1. Agree scope with OT operations: approved hosts, PLCs and gateways, maintenance windows, capture duration and evidence handling.
2. Collect both directions from an approved TAP or SPAN port. Do not probe, replay traffic or send test writes or diagnostics. Keep the original PCAP, the capture-point details, the clock reference and the packet-loss statistics.
3. Analyze a copy offline. Decoded values and payloads expose process data, so retain payloads only as the site's data-handling policy allows.

```bash
net capture -read plant.pcap -out modbus-hunt -include Modbus -reassemble-connections=true -payload -compress=true
net dump -read modbus-hunt/Modbus.ncap.gz -json
net dump -read modbus-hunt/Modbus.ncap.gz -fields     # exact field list for this build
```

`Modbus` is both the TCP stream decoder and the audit-record name. TCP/502 is only the convention. Netcap detects Modbus by content, so other ports work. It claims a conversation once one complete ADU decodes, because an MBAP header alone is too weak a signature (LDAP's BER framing satisfies every field of it). A conversation whose first complete ADU never arrives is not claimed.

Each TCP direction is framed independently, and an ADU's timestamp is its first captured byte. With `-allowmissinginit=true` (the default), an unknown starting boundary is accepted only before any payload has been consumed. Any other interruption writes a `lost` marker for that direction while the other direction continues.

After a gap of known size, the decoder discards the buffered bytes and validates the MBAP header once, at the first byte after the gap. It never scans forward for a header. If that check fails, the direction stays stopped for the rest of the conversation, as it does after an invalid MBAP header or a gap of unknown size. Incomplete trailing ADUs are not emitted but leave a marker.

Stream records are written when the connection completes or flushes, so this is not a real-time alerting path.

## Field Reference

| Field(s)                                                                                                            | Meaning                                                                                                                                                                                                                                                                                         |
| ------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Timestamp`                                                                                                         | Integer Unix nanoseconds of the ADU's first captured byte.                                                                                                                                                                                                                                      |
| `SrcIP`, `DstIP`, `SrcPort`, `DstPort`, `CommunityID`                                                               | Endpoints and flow ID, set per direction, so a response has the PLC as `SrcIP`. These are addresses, not authenticated identities.                                                                                                                                                              |
| `Transport`                                                                                                         | `tcp` (MBAP) or `rtu_tcp` (RTU frames over TCP, opt-in).                                                                                                                                                                                                                                        |
| `MessageRole`                                                                                                       | `request`, `response`, or `unknown` when the stream direction could not be established.                                                                                                                                                                                                         |
| `ParseStatus`, `ParseError`                                                                                         | `valid`, `malformed` (with a reason), `unsupported`, or `lost` on a capture-loss marker. Malformed records carry only the function code, exception flag and framing metadata, with no decoded values.                                                                                           |
| `HasMBAP`, `TransactionID`, `ProtocolID`, `Length`, `UnitID`                                                        | MBAP metadata; `HasMBAP` is false for RTU. `Length` counts the unit byte plus the PDU. `UnitID` identifies a unit behind an endpoint, not a user.                                                                                                                                               |
| `Exception`, `ExceptionCode`                                                                                        | The exception bit (stripped from the function code) and the nonzero exception code as sent. Only responses can carry an exception; an exception PDU seen as a request is `malformed`.                                                                                                           |
| `Bank`                                                                                                              | `coils` (FC1/5/15), `discrete_inputs` (FC2), `holding_registers` (FC3/6/16/22/23), `input_registers` (FC4), `file_records` (FC20/21). Empty for FC7, 8, 11, 12, 17, 24 and 43.                                                                                                                  |
| `HasAddress`, `Address`, `Quantity`, `Values`                                                                       | Zero-based wire start address, count and values for FC1-6, 15, 16, 22. `Values` holds coil bits as 0/1 and registers as 16-bit words. FC23 responses return their read data in `Values`/`ReadQuantity`.                                                                                         |
| `HasReadAddress`, `ReadAddress`, `ReadQuantity` / `HasWriteAddress`, `WriteAddress`, `WriteQuantity`, `WriteValues` | FC23 only. Single and multiple writes use `Address`/`Quantity`/`Values`.                                                                                                                                                                                                                        |
| `AndMask`, `OrMask`                                                                                                 | FC22 mask-write operands (`Address` set, `Quantity` 1).                                                                                                                                                                                                                                         |
| `HasDiagnostic`, `DiagnosticSubfunction`, `DiagnosticData`                                                          | FC8 subfunction and its data words.                                                                                                                                                                                                                                                             |
| `Values`, `Quantity` for FC7/11/12                                                                                  | Serial-oriented status replies. The requests carry no data. FC7: one exception-status byte in `Values`. FC11: the status and event-count words. FC12: three header words (status, event count, message count), then `Quantity` entries, each one raw event byte that is not decoded into flags. |
| `HasAddress`, `Address`, `Quantity`, `Values` for FC24                                                              | The request carries the FIFO pointer in `Address`. The response sets `Quantity` to the FIFO count (max 31) and `Values` to the queued registers.                                                                                                                                                |
| `Quantity`, `Payload` for FC17                                                                                      | Netcap checks only the framing. `Quantity` is the response byte count. The vendor-defined content after it stays in `Payload` (needs `-payload`). No `Values`, address or bank.                                                                                                                 |
| `MEIType`, `ReadDeviceIDCode`, `DeviceIDObjectID`                                                                   | FC43 request: MEI type (14 = Read Device Identification) and the requested ID code and object. Other MEI types are `unsupported`.                                                                                                                                                               |
| `DeviceIDObjects`, `DeviceIDConformityLevel`, `DeviceIDMoreFollows`, `DeviceIDNextObjectID`                         | FC43 MEI14 response: vendor, product and revision objects as `{ID, Value}`, with `Value` as raw bytes (base64 in JSON).                                                                                                                                                                         |
| `FileRecords`                                                                                                       | FC20/21 records as `{ReferenceType, FileNumber, RecordNumber, RecordLength, Values}`. File numbers and record offsets are not register addresses.                                                                                                                                               |
| `CorrelationStatus`, `RequestTimestamp`, `ResponseLatency`                                                          | `matched`, `unmatched`, `ambiguous` or `not_applicable`. `RequestTimestamp` and `ResponseLatency` (nanoseconds) are set only on matched responses.                                                                                                                                              |
| `HasChecksum`, `ChecksumValid`, `Broadcast`                                                                         | RTU only. Frames that fail the CRC are never emitted, so `ChecksumValid` is always true when `HasChecksum` is true. `Broadcast` marks a unit-0 write.                                                                                                                                           |
| `LostBytes`                                                                                                         | Only on `ParseStatus == "lost"` markers: `> 0` is the gap size reassembly reported, `-1` means the size is unknown, `0` means the capture was contiguous but framing became unusable. Zero on every decoded record.                                                                             |
| `Payload`                                                                                                           | The raw PDU (no MBAP, no unit byte, no CRC) when captured with `-payload`. Base64 in JSON, hex in CSV.                                                                                                                                                                                          |

A `matched` response gets extra fields from its request. Read responses (FC1-4) inherit `Address` and `Quantity`, and coil bit padding is trimmed to the requested quantity. FC23 inherits the request's `Read*` and `Write*` fields. FC20 subresponses inherit `FileNumber` and `RecordNumber`. An unmatched FC3 response has values but no address.

Classic Modbus has no user identity and no authentication. An IP allowlist says which equipment you expect, not who authorized an operation. Use workstation, access and change logs for attribution.

## Capture Loss

When a direction stops producing evidence, Netcap writes exactly one marker record per loss event: `ParseStatus == "lost"`, `MessageRole == "unknown"`, `CorrelationStatus == "not_applicable"`, `LostBytes` as above, plus `Transport`, the direction's endpoints and its last-seen timestamp. No function code, address or value is set. Further markers are suppressed until that direction decodes a record again. `ParseError` names the cause: `capture gap`, `unusable fragment`, `invalid MBAP header` or `truncated ADU`, and over RTU `unframed bytes discarded` or `unframed trailing bytes`.

```bash
net dump -read modbus-hunt/Modbus.ncap.gz -json -filter 'ParseStatus == "lost"'
```

Correlation does not survive a loss. Requests outstanding at the gap become `ambiguous`, because their responses may have passed unseen. Over MBAP, requests seen after the gap correlate normally. Over RTU, a loss blocks correlation for the rest of the conversation.

Check for markers on the endpoints and time range you care about before you report a negative result. An empty hunt over a conversation with loss markers is incomplete.

## Output Semantics

`net dump -json` emits integer nanosecond timestamps and base64 bytes. The Elasticsearch-oriented `Modbus.JSON()` method converts `Timestamp`, but not `RequestTimestamp`, to milliseconds. CSV renders `Values`, `WriteValues`, `DeviceIDObjects` and `FileRecords` as JSON cells, `Payload` and `DiagnosticData` as hex, and `ResponseLatency` as plain nanoseconds. `-select` projects columns in CSV and table output; it does not redact JSON.

The numeric encoding is lossy. Strings, byte fields and repeated fields (`Values`, `FileRecords`, `DeviceIDObjects`, `Payload`, `CommunityID`, `Bank`, `MessageRole` and others) are hashed to the low 16 bits of IEEE CRC32 and normalized, with no dictionary. Collisions happen, the buckets carry no order or distance, and the result is not anonymized. Use CSV, JSON or protobuf when you need exact values.

The `nc_modbus` Prometheus counter has only `FunctionCode` and `Exception` labels. It counts observed ADUs, including replies and exceptions, not successful writes.

## Scoped Baseline

Build a baseline per cell or process, endpoint pair and UnitID. Cover routine polling, startup, shutdown and approved maintenance. Record the approved function codes, banks and complete wire address intervals (not just start addresses) plus the operating windows, and have the OT owners confirm the exceptions. Compare captures of similar duration and visibility. Peers you see in the capture are baseline candidates until someone confirms them as authorized masters.

Start with the raw request inventory:

```bash
net dump -read modbus-hunt/Modbus.ncap.gz -json \
  -filter 'MessageRole == "request" && ParseStatus == "valid" && !Exception'
```

## Primary Hunt: Unauthorized Writes

Start every operational hunt with `MessageRole == "request" && ParseStatus == "valid"`. That drops echo replies (FC5/6/22 responses are byte-identical to their requests), malformed PDUs, and midstream `unknown` records.

The approved set must cover the whole written interval, per bank. FC5/6/15/16/22 use `Address`/`Quantity`; FC23 uses `WriteAddress`/`WriteQuantity`.

In the example, the HMI (192.168.1.20) may write coils 100-199 and holding registers 1000-1099 on the PLC (192.168.1.10, unit 1). Any other write, from any host, matches:

```bash
net dump -read modbus-hunt/Modbus.ncap.gz -json -filter '
MessageRole == "request" && ParseStatus == "valid" && !Exception &&
FunctionCode in [5, 6, 15, 16, 22, 23] &&
!(SrcIP == "192.168.1.20" && DstIP == "192.168.1.10" && UnitID == 1 &&
  ((FunctionCode in [5, 15] && Bank == "coils" && HasAddress && Quantity > 0 &&
    Address >= 100 && Address <= 199 && Quantity <= 200 - Address) ||
   (FunctionCode in [6, 16, 22] && Bank == "holding_registers" && HasAddress && Quantity > 0 &&
    Address >= 1000 && Address <= 1099 && Quantity <= 1100 - Address) ||
   (FunctionCode == 23 && Bank == "holding_registers" && HasWriteAddress && WriteQuantity > 0 &&
    WriteAddress >= 1000 && WriteAddress <= 1099 && WriteQuantity <= 1100 - WriteAddress)))'
```

Put the upper-bound check (`Address <= 199`) before the span check. It expresses containment and keeps the unsigned subtraction from wrapping. An approved master that writes outside its ranges still matches, which is the point.

FC21 file writes need their own rule. Approve `FileNumber` and the full `RecordNumber`..`RecordNumber + RecordLength` interval of every record. `all()` is true on an empty list, so guard it: `len(FileRecords) > 0 && all(FileRecords, {.ReferenceType == 6 && .FileNumber == 1 && .RecordNumber >= 100 && .RecordNumber <= 199 && .RecordLength > 0 && .RecordLength <= 200 - .RecordNumber})`.

A match is a write request. To see whether the device accepted it, look at the correlated response:

```bash
net dump -read modbus-hunt/Modbus.ncap.gz -json \
  -filter 'MessageRole == "response" && CorrelationStatus == "matched" && FunctionCode in [5, 6, 15, 16, 21, 22, 23]'
```

## Diagnostics And Discovery

```bash
# FC8 subfunctions that can disrupt a device: restart comms (1), force listen-only (4), clear counters (10)
net dump -read modbus-hunt/Modbus.ncap.gz -json \
  -filter 'MessageRole == "request" && ParseStatus == "valid" && FunctionCode == 8 && HasDiagnostic && DiagnosticSubfunction in [1, 4, 10]'

# FC43 MEI14 device identification
net dump -read modbus-hunt/Modbus.ncap.gz -json \
  -filter 'MessageRole == "request" && ParseStatus == "valid" && FunctionCode == 43 && MEIType == 14'

# Identity strings returned in the responses
net dump -read modbus-hunt/Modbus.ncap.gz -json \
  -filter 'MessageRole == "response" && ParseStatus == "valid" && MEIType == 14 && len(DeviceIDObjects) > 0'

# FC17 Report Server ID, and the serial-oriented status queries FC7/11/12
net dump -read modbus-hunt/Modbus.ncap.gz -json \
  -filter 'MessageRole == "request" && ParseStatus == "valid" && FunctionCode in [7, 11, 12, 17]'
```

FC8 diagnostics come from serial lines, and TCP gateways and devices differ in what they support. Force listen-only (subfunction 4) has no response, so it is never `matched`. Asset-inventory tools legitimately read identity data, so treat FC43 and FC17 hits as triage. FC17's vendor content is not decoded; read it from `Payload` by hand, and do not assume the layout is shared between vendors. Never send any of these requests to production equipment to validate a finding.

## Exceptions

```bash
# Illegal data address, attributable to a specific initiating master
net dump -read modbus-hunt/Modbus.ncap.gz -json \
  -filter 'MessageRole == "response" && Exception && ExceptionCode == 2 && CorrelationStatus == "matched"'

# All exceptions, including those with no recoverable request
net dump -read modbus-hunt/Modbus.ncap.gz -json -filter 'Exception'
```

Common codes: 1 illegal function, 2 illegal data address, 3 illegal data value, 4 device failure, 6 device busy, 10/11 gateway path/target failure. On `matched` responses, `DstIP` is the initiating master, and `RequestTimestamp` and `ResponseLatency` are set. On `unmatched` responses you cannot recover the request or the address.

## Enumeration

The rule engine counts distinct values in a time window with `distinct_field`, `distinct_threshold` and `threshold_window`. That finds breadth, not scan order. For ordered pairing see [Read-Then-Write Pairing](modbus-threat-hunting.md#read-then-write-pairing).

* `distinct_field: DstIP`: one source touching many controllers.
* `distinct_field: UnitID`, scoped to one `DstIP`: a unit sweep behind a gateway.
* `distinct_field: Address` (or `ReadAddress` for FC23), scoped to one destination, unit and bank: register map probing. It counts distinct start addresses, not covered addresses.

## Read-Then-Write Pairing

A rule can require an earlier related record before it alerts, so you can pair a read with a later write of the same register inside the rule engine. `internal/rules/examples/modbus_hunt.yml` ships this as `Modbus Write After Read Same Register`, disabled:

```yaml
expression: >-
  MessageRole == "request" && ParseStatus == "valid" && !Exception &&
  FunctionCode in [6, 16, 22] && Bank == "holding_registers" && HasAddress
sequence:
  after: >-
    MessageRole == "request" && ParseStatus == "valid" && !Exception &&
    FunctionCode == 3 && Bank == "holding_registers" && HasAddress
  group_by: [SrcIP, DstIP, UnitID, Bank, Address]
  within: 900
```

It fires when the same `SrcIP`, `DstIP`, `UnitID` and `Bank` read a start address with FC3 and, within 900 seconds, wrote to the same start address. `group_by` is exact equality, so a write that only overlaps the read span does not match. To widen the hunt, drop `Address` from `group_by` and expect more volume. Records missing a group field are not correlated. The write must be timestamped at or after the read, and records that reach the engine out of order do not pair. Both halves must have decoded, and a `lost` marker between them means the read may never have been seen.

HMI setpoint edits, controller retuning and any client that reads a register before writing it back produce this pattern all the time. Compare matches to the polling baseline and the register map. The alert contains only the write, so fetch the earlier read from `Modbus.ncap.gz` with the same tuple and window:

```bash
net dump -read modbus-hunt/Modbus.ncap.gz -json -filter '
MessageRole == "request" && ParseStatus == "valid" && FunctionCode == 3 &&
SrcIP == "192.168.1.20" && DstIP == "192.168.1.10" && UnitID == 1 &&
Bank == "holding_registers" && Address == 1000'
```

## Running The Shipped Rules

`internal/rules/examples/modbus_hunt.yml` contains 15 rules: request-level hunt templates, one read-then-write pairing template, enumeration templates, and visibility and coverage triage. Rules that depend on your site use documentation IPs and ship with `enabled: false`. Replace the addresses, units, banks and intervals before you enable them. `Modbus Write After Read Same Register` needs no site values but also ships disabled, because read-modify-write masters match it routinely.

Six site-independent rules are enabled by default: device identification (FC43 MEI14), server identification (FC17), disruptive diagnostics (FC8 subfunctions 1/4/10), unknown-role triage, parse triage (`malformed`/`unsupported`), and capture loss (`lost`). No rule triggers a response action.

```bash
net capture -read plant.pcap -out modbus-hunt -include Modbus \
  -reassemble-connections=true -payload -rules internal/rules/examples/modbus_hunt.yml
net dump -read modbus-hunt/Alert.ncap.gz -json
```

The shipped write template approves the `Address`/`Quantity` form and the FC23 `WriteAddress`/`WriteQuantity` form separately. Keep both clauses when you substitute your own values, or approved FC23 writes will alert.

Keep the capture-loss rule enabled. It does not signal an attack; it tells you whether a quiet result means no traffic or a direction that stopped decoding.

Instead of inline addresses, you can load an IP list with `-approved-workstations` and use the `IsApprovedWorkstation()` rule helper. See [Rules Engine](RULES_ENGINE.md) and [Filtering](FILTERING.md).

## RTU Over TCP

RTU framing (unit byte, PDU, CRC16, no MBAP) is decoded only for endpoints you name:

```bash
net capture -read gateway.pcap -out modbus-hunt -include Modbus \
  -reassemble-connections=true -payload \
  -modbus-rtu-endpoints '192.168.1.30:1502,[2001:db8::1]:502'
```

`net export` takes the same flag, and both read `NC_MODBUS_RTU_ENDPOINTS`. Values are comma-separated `IP:port` or `[IPv6]:port` with a nonzero port, and an invalid entry fails decoder initialization. Matching is exact on the server address and port (or the client side when no handshake was seen, since a midstream capture can have its direction reversed). There is no CIDR, hostname or wildcard form and no autodetection. A listed endpoint takes priority over every other decoder and turns off MBAP parsing for that conversation, so do not list an MBAP endpoint.

RTU records set `Transport == "rtu_tcp"`, `HasChecksum`, `ChecksumValid` and `UnitID`. `HasMBAP` is false, and `TransactionID`, `ProtocolID` and `Length` are zero. Correlation allows one outstanding request per conversation, matched on unit, function code and response shape within 30 seconds. A loss blocks it for the rest of the conversation. Unit-0 frames are accepted only as write requests and the diagnostics permitted for unit 0. They are marked `Broadcast` with `CorrelationStatus == "not_applicable"`, since no response is expected. The four-byte empty-request functions (FC7, 11, 12, 17) and FC24 are framed and correlated too.

Only frames that pass the CRC and parse to a valid PDU are emitted. Vendor-specific and unmodelled functions never become records, but bytes that never framed show up as `unframed bytes discarded` or `unframed trailing bytes` loss markers.

## Manual Payload Evidence

* **Addresses:** `Address` is the zero-based wire offset within the bank the function selects. A holding register labelled `40001` usually means `Address == 0`, but vendor conventions vary. Keep coils, discrete inputs, input registers and holding registers apart. `UnitID` is not an address. Confirm offset, width, scaling, signedness and multi-register word order against the device's register map before you assign a process meaning to a value.
* **Direction:** FC5/6/22 responses echo their requests byte for byte, so field values alone do not show who initiated. `MessageRole` comes from the stream direction and is only as reliable as the capture.
* **Payload:** byte 0 of `Payload` is the wire function code with the exception bit intact. There is no MBAP header or CRC in it. Decode the base64 before you read the bytes. If payloads are missing, reprocess the retained PCAP with `-payload`.

For escalation, keep the PCAP and frame references, endpoint pair, UnitID, transaction number, decoded record, correlation status, the deviation from baseline and the OT owner's assessment.

## Limitations

* **No user identity.** Records attribute to endpoints and units only.
* **`unknown` roles.** Without an observed handshake the direction is unknown. For FC1-4 and FC20, where request and response layouts are both plausible, Netcap emits only `FunctionCode` and `Bank`, with no address, quantity or values. Do not count these as writes.
* **Correlation.** Correlation is per TCP connection, keyed on transaction ID with unit, function and shape checks, a 30-second window and a cap of 1024 pending requests. Duplicate transaction IDs, saturation or loss mark records `ambiguous`. Responses whose request was not seen stay `unmatched`. Do not join on transaction ID across connections.
* **Gaps.** A `lost` marker tells you decoding stopped or resynchronised. It does not recover the missing ADUs, and everything between the marker and the next decoded record is unobserved.
* **Gateways.** A TCP-to-RTU gateway exposes only its TCP side. `UnitID` gives no view of the serial bus behind it.
* **Encrypted transport** needs plaintext evidence from elsewhere.

## Remaining Gaps

* No native serial capture and no Modbus ASCII. Only MBAP over TCP and RTU frames carried over TCP are decoded.
* Vendor-defined function codes (65-72 and 100-110), any other unmodelled code, and FC43 with an MEI type other than 14 produce `ParseStatus == "unsupported"` with no structured fields. Over RTU they never frame and appear only as loss markers.
* FC17's vendor content is framed but not interpreted, and FC12 event bytes are raw codes.
* Ordered correlation is one earlier record, matched by exact field equality. There are no multi-step chains and no range-overlap join. To pair a write with a read whose span covers it, export the records and join them yourself.

See [Filtering](FILTERING.md) for expression syntax and [Industrial Control Systems](industrial-control-systems.md) for other protocols.
