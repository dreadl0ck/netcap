# Modbus Threat Hunting

Netcap decodes Modbus into structured audit records: request/response role,
per-function addresses, quantities and values, diagnostics, device and server
identification, file records, exception codes, request/response correlation, and
explicit markers for data it could not decode. Use it for passive inventory and
hypothesis-driven triage, then validate candidates against the original capture
and the site's register map. A matching record is not proof of an unauthorized
command or a process change.

## Capture Safely

1. Agree scope with OT operations: approved hosts, PLCs/gateways, maintenance windows, capture duration and evidence handling.
2. Collect both directions from an approved TAP/SPAN point, without probing, replaying traffic or issuing test writes/diagnostics. Preserve the original PCAP, capture-point details, clock reference and packet-loss statistics.
3. Analyze a copy offline. Retain payloads only under the site's data-handling policy; decoded values and payloads expose process data and settings.

```bash
net capture -read plant.pcap -out modbus-hunt -include Modbus -reassemble-connections=true -payload -compress=true
net dump -read modbus-hunt/Modbus.ncap.gz -json
net dump -read modbus-hunt/Modbus.ncap.gz -fields     # exact field list for this build
```

`Modbus` is the TCP stream decoder and the audit-record name. TCP/502 is
conventional, not required: the MBAP signature (`ProtocolID == 0`, sane length,
known function code) supports port-independent detection. Do not restrict
collection to port 502 if nonstandard-port use is in scope. Signature detection
is not a completeness guarantee; missing bytes, partial captures and unsupported
traffic leave gaps. No records does not prove no Modbus activity.

The decoder frames each TCP direction independently and timestamps an ADU from
its first captured byte. With `-allowmissinginit=true` (the default), an unknown
initial boundary is accepted only before any payload has been consumed. Every
other interruption emits a `lost` marker record and is handled per direction;
the opposite direction continues. After a gap of a **known** size the buffered
bytes are discarded and the first byte after the gap is the only resume point:
the MBAP header is validated exactly once at that offset, and the decoder never
scans forward through a body hunting for a header. If that single attempt fails
the direction stays stopped for the rest of the conversation — as it does after
an invalid MBAP header or a gap of unknown extent. Incomplete trailing ADUs are
still not emitted, but they now leave a marker. **Stream records are written at
connection completion/flush**, not when a command arrives — this is not a
real-time alerting path.

## Field Reference

| Field(s) | Meaning and limit |
| --- | --- |
| `Timestamp` | Integer Unix nanoseconds; first captured byte of the ADU. |
| `SrcIP`, `DstIP`, `SrcPort`, `DstPort`, `CommunityID` | Endpoints and flow ID. Not authenticated identities. Rewritten per direction, so a response has the PLC as `SrcIP`. |
| `Transport` | `tcp` (MBAP) or `rtu_tcp` (RTU frames over TCP, opt-in). |
| `MessageRole` | `request`, `response`, or `unknown` when stream direction could not be established. |
| `ParseStatus`, `ParseError` | `valid`, `malformed` (with a reason), `unsupported`, or `lost` on a capture-loss marker. Malformed records carry **no** decoded values — only function code, exception flag and framing metadata. |
| `HasMBAP`, `TransactionID`, `ProtocolID`, `Length`, `UnitID` | MBAP metadata; `HasMBAP` is false for RTU. `Length` counts the unit byte plus PDU. `UnitID` identifies a unit behind an endpoint, not a user. |
| `Exception`, `ExceptionCode` | Exception bit stripped from the function code, plus the nonzero exception code as sent. Only responses may carry an exception; an exception PDU seen as a request is `malformed`. |
| `Bank` | `coils` (FC1/5/15), `discrete_inputs` (FC2), `holding_registers` (FC3/6/16/22/23), `input_registers` (FC4), `file_records` (FC20/21). Empty for FC7, 8, 11, 12, 17, 24 and 43. |
| `HasAddress`, `Address`, `Quantity`, `Values` | Wire (zero-based) start address, count and values for FC1-6, 15, 16, 22. `Values` holds coil bits as 0/1 and registers as 16-bit words; FC23 responses also return their read data in `Values`/`ReadQuantity`. |
| `HasReadAddress`, `ReadAddress`, `ReadQuantity` / `HasWriteAddress`, `WriteAddress`, `WriteQuantity`, `WriteValues` | **FC23 only.** No other function populates the `Read*`/`Write*` fields; single/multiple writes use `Address`/`Quantity`/`Values`. |
| `AndMask`, `OrMask` | FC22 mask-write operands (`Address` set, `Quantity` 1). |
| `HasDiagnostic`, `DiagnosticSubfunction`, `DiagnosticData` | FC8 subfunction and its data words. |
| `Values`, `Quantity` for FC7/11/12 | Serial-oriented status replies; all three requests carry no data at all. FC7: one exception-status byte in `Values`. FC11: the status and event-count words. FC12: three header words (status, event count, message count) followed by `Quantity` further entries, each one **raw event byte** — the event codes are not decoded into flags. |
| `HasAddress`, `Address`, `Quantity`, `Values` for FC24 | Request carries only the FIFO pointer in `Address`. Response sets `Quantity` to the FIFO count (max 31) and `Values` to the queued registers. |
| `Quantity`, `Payload` for FC17 | Only the framing is checked. `Quantity` is the response byte count; the vendor-defined content after it is deliberately **not parsed** and stays in `Payload` (so it needs `-payload`). No `Values`, no address, no bank. |
| `MEIType`, `ReadDeviceIDCode`, `DeviceIDObjectID` | FC43 request: MEI type (14 = Read Device Identification) and requested ID code/object. Other MEI types are `unsupported`. |
| `DeviceIDObjects`, `DeviceIDConformityLevel`, `DeviceIDMoreFollows`, `DeviceIDNextObjectID` | FC43 MEI14 response: vendor/product/revision objects as `{ID, Value}` with `Value` raw bytes (base64 in JSON). |
| `FileRecords` | FC20/21 records as `{ReferenceType, FileNumber, RecordNumber, RecordLength, Values}`. File numbers and record offsets are **not** register addresses. |
| `CorrelationStatus`, `RequestTimestamp`, `ResponseLatency` | `matched`, `unmatched`, `ambiguous` or `not_applicable`. `RequestTimestamp`/`ResponseLatency` (nanoseconds) are set only on matched responses. |
| `HasChecksum`, `ChecksumValid`, `Broadcast` | RTU only. Frames failing CRC are never emitted, so `ChecksumValid` is always true when `HasChecksum` is true. `Broadcast` marks a unit-0 write. |
| `LostBytes` | Set only on `ParseStatus == "lost"` markers: `> 0` is the gap size reassembly reported, `-1` means the amount is unknown, `0` means the capture was contiguous but framing became unusable. Zero on every decoded record. |
| `Payload` | Raw PDU only (no MBAP, no unit byte, no CRC) when captured with `-payload`; base64 in JSON, hex in CSV. |

Response enrichment on `CorrelationStatus == "matched"`: read responses (FC1-4)
inherit `Address`/`Quantity` from their request and coil bit padding is trimmed
to the requested quantity; FC23 inherits the request's `Read*`/`Write*` fields;
FC20 subresponses inherit `FileNumber`/`RecordNumber`. Unmatched responses lack
all of this — an unmatched FC3 response has values but no address.

Classic Modbus has **no protocol user identity and no authentication**. An IP
allowlist expresses expected equipment, not which person authorized an
operation. Use workstation, access and change logs for attribution.

## Capture Loss

A direction that stops producing evidence emits **exactly one** marker record
per loss event: `ParseStatus == "lost"`, `MessageRole == "unknown"`,
`CorrelationStatus == "not_applicable"`, `LostBytes` as described above, and
`Transport` plus the direction's endpoints and last-seen timestamp. No function
code, address or value is set. Further markers are suppressed until that
direction decodes a record again. `ParseError` names the cause — `capture gap`,
`unusable fragment`, `invalid MBAP header` or `truncated ADU`, and over RTU
`unframed bytes discarded` or `unframed trailing bytes`.

```bash
net dump -read modbus-hunt/Modbus.ncap.gz -json -filter 'ParseStatus == "lost"'
```

Correlation does not survive a loss. Requests outstanding when the gap occurred
become `ambiguous`, because their response may have passed unseen and a later
response reusing the transaction ID would not be evidence of a match; MBAP
requests observed after the gap correlate normally, whereas over RTU a loss
blocks correlation for the rest of the conversation.

Markers make coverage auditable: **an empty hunt result over a conversation
that also produced loss markers is not evidence of absence.** Check for markers
on the endpoints and time range in question before reporting a negative
finding, and treat every hunt over an affected conversation as incomplete.

## Output Semantics

`net dump -json` emits integer nanosecond timestamps and base64 bytes. The
Elasticsearch-oriented `Modbus.JSON()` method converts `Timestamp` — but not
`RequestTimestamp` — to milliseconds. CSV renders `Values`, `WriteValues`,
`DeviceIDObjects` and `FileRecords` as JSON cells, `Payload`/`DiagnosticData` as
hex, and `ResponseLatency` as plain nanoseconds. `-select` is CSV/table
projection, not JSON redaction.

Numeric encoding is not an evidence export: strings, byte fields and repeated
fields (`Values`, `FileRecords`, `DeviceIDObjects`, `Payload`, `CommunityID`,
`Bank`, `MessageRole`, ...) are hashed to the low 16 bits of IEEE CRC32 and then
normalized, with no dictionary. Collisions are intentional; these buckets imply
neither ordering nor distance and are not anonymization. Use CSV, JSON or
protobuf when exact values are required.

The `nc_modbus` Prometheus counter still exposes only `FunctionCode` and
`Exception` labels — not roles, addresses, values or endpoints. It counts
observed ADUs, including replies and exceptions; these are not successful-write
counts.

## Scoped Baseline

Build a known-good baseline per cell/process, endpoint pair and UnitID covering
routine polling, startup/shutdown and approved maintenance. Record approved
function codes, banks and **complete wire address intervals** — not just start
addresses — plus operating windows, and have OT owners confirm exceptions.
Compare like capture durations and visibility. One plant-wide allowlist is not a
process baseline. Observed peers are baseline candidates, not authorized masters.

Collect the raw request inventory first:

```bash
net dump -read modbus-hunt/Modbus.ncap.gz -json \
  -filter 'MessageRole == "request" && ParseStatus == "valid" && !Exception'
```

## Primary Hunt: Unauthorized Writes

Gate every operational hunt on `MessageRole == "request" && ParseStatus ==
"valid"`. This excludes echo replies (FC5/6/22 responses are byte-identical to
their requests), excludes malformed PDUs whose decoded fields are deliberately
suppressed, and excludes midstream `unknown` records.

Approval must contain the **whole written interval**, not the start address, and
must be expressed per bank. Note the field split: FC5/6/15/16/22 use
`Address`/`Quantity`; FC23 uses `WriteAddress`/`WriteQuantity`.

```bash
net dump -read modbus-hunt/Modbus.ncap.gz -json -filter '
MessageRole == "request" && ParseStatus == "valid" && !Exception &&
FunctionCode in [5, 6, 15, 16, 22, 23] &&
!(SrcIP == "192.0.2.10" && DstIP == "192.0.2.20" && UnitID == 1 &&
  ((FunctionCode in [5, 15] && Bank == "coils" && HasAddress && Quantity > 0 &&
    Address >= 100 && Address <= 199 && Quantity <= 200 - Address) ||
   (FunctionCode in [6, 16, 22] && Bank == "holding_registers" && HasAddress && Quantity > 0 &&
    Address >= 1000 && Address <= 1099 && Quantity <= 1100 - Address) ||
   (FunctionCode == 23 && Bank == "holding_registers" && HasWriteAddress && WriteQuantity > 0 &&
    WriteAddress >= 1000 && WriteAddress <= 1099 && WriteQuantity <= 1100 - WriteAddress)))'
```

The upper-bound check (`Address <= 199`) must precede the span check, both to
express containment and to keep the unsigned subtraction from wrapping. An
approved master writing outside its ranges still matches — that is the point.

FC21 file writes need their own rule; approve `FileNumber` and the full
`RecordNumber`..`RecordNumber + RecordLength` interval of every record. `all()`
is vacuously true on an empty list, so guard it:
`len(FileRecords) > 0 && all(FileRecords, {.ReferenceType == 6 && .FileNumber == 1 && .RecordNumber >= 100 && .RecordNumber <= 199 && .RecordLength > 0 && .RecordLength <= 200 - .RecordNumber})`.

A match is an **attempted** write. Pair it with the correlated response before
claiming effect:

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

# Harvested identity strings from the responses
net dump -read modbus-hunt/Modbus.ncap.gz -json \
  -filter 'MessageRole == "response" && ParseStatus == "valid" && MEIType == 14 && len(DeviceIDObjects) > 0'

# FC17 Report Server ID, and the serial-oriented status queries FC7/11/12
net dump -read modbus-hunt/Modbus.ncap.gz -json \
  -filter 'MessageRole == "request" && ParseStatus == "valid" && FunctionCode in [7, 11, 12, 17]'
```

FC8 diagnostics are serial-line-oriented; TCP gateways and devices vary in
support, and a request is not evidence that disruption occurred. Force
listen-only (subfunction 4) has no response, so it is never `matched`.
Inventory tools legitimately enumerate identity data, so FC43 and FC17 are
triage, not findings. FC17's reply is framed but its vendor content is not
decoded — read it out of `Payload` by hand, and do not assume a shared layout
across vendors. Never issue any of these to validate a finding on production
equipment.

## Exceptions

```bash
# Illegal data address, attributable to a specific initiating master
net dump -read modbus-hunt/Modbus.ncap.gz -json \
  -filter 'MessageRole == "response" && Exception && ExceptionCode == 2 && CorrelationStatus == "matched"'

# All exceptions including those with no recoverable request
net dump -read modbus-hunt/Modbus.ncap.gz -json -filter 'Exception'
```

Common codes: 1 illegal function, 2 illegal data address, 3 illegal data value,
4 device failure, 6 device busy, 10/11 gateway path/target failure. An exception
is not a completed write, and the absence of one does not establish execution.
On `matched` responses `DstIP` is the initiating master and `RequestTimestamp`
and `ResponseLatency` are populated; on `unmatched` responses neither the
originating request nor the requested address is recoverable.

## Enumeration

Netcap's rule engine counts distinct values in a time window. Cardinality
carries no ordering, so these detect breadth, not a scan pattern; for ordered
pairing see [Read-Then-Write Pairing](#read-then-write-pairing) below.
Use `distinct_field` with `distinct_threshold` and `threshold_window`:

- `distinct_field: DstIP` — one source touching many controllers.
- `distinct_field: UnitID` scoped to one `DstIP` — unit sweeping behind a gateway.
- `distinct_field: Address` (or `ReadAddress` for FC23) scoped to one destination/unit/bank — register map probing. This counts distinct **start** addresses, not covered addresses.

## Read-Then-Write Pairing

A rule can require an earlier related record before it alerts, so pairing a read
with a later write of the same register is a rule, not a post-export step.
`rules/examples/modbus_hunt.yml` ships this as `Modbus Write After Read Same
Register`, **disabled**:

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

What it asserts is narrow: the same `SrcIP`/`DstIP`/`UnitID`/`Bank` issued an
FC3 read of a start address and then, within 900 seconds, a write to **the same
start address**. `group_by` is exact equality, so a write whose span merely
overlaps an earlier read is not matched — widen the hunt by dropping `Address`
from `group_by` and accept the extra volume. A record missing a group field is
not correlated at all, and the write must be timestamped at or after the read;
records reaching the engine out of order do not pair. Because records are
emitted at connection completion/flush, both halves must have decoded before a
pair can form, and a `lost` marker between them means the read may never have
been observed.

Read-modify-write masters produce exactly this pattern legitimately and
constantly: HMI setpoint edits, controller retuning, and any client that reads a
register before writing it back. A match is a candidate for baseline comparison,
**not** proof of reconnaissance preceding a change or of staged tampering.
Confirm it against the polling baseline and the register map. The alert
describes the write only — the earlier read is not attached, so retrieve it from
`Modbus.ncap.gz` with the same tuple and window:

```bash
net dump -read modbus-hunt/Modbus.ncap.gz -json -filter '
MessageRole == "request" && ParseStatus == "valid" && FunctionCode == 3 &&
SrcIP == "192.0.2.10" && DstIP == "192.0.2.20" && UnitID == 1 &&
Bank == "holding_registers" && Address == 1000'
```

## Running The Shipped Rules

`rules/examples/modbus_hunt.yml` contains 15 rules: request-level hunt
templates, one read-then-write pairing template, enumeration templates, and
visibility/coverage triage. Site-dependent rules use documentation IPs and ship
`enabled: false`; replace the addresses, units, banks and intervals before
enabling. `Modbus Write After Read Same Register` needs no site values but also
ships disabled, because read-modify-write masters match it routinely. Six
site-independent rules are enabled by default — device identification (FC43
MEI14), server identification (FC17), disruptive diagnostics (FC8 subfunctions
1/4/10), unknown-role triage, parse triage (`malformed`/`unsupported`), and
capture loss (`lost`). No rule configures a response action.

```bash
net capture -read plant.pcap -out modbus-hunt -include Modbus \
  -reassemble-connections=true -payload -rules rules/examples/modbus_hunt.yml
net dump -read modbus-hunt/Alert.ncap.gz -json
```

The shipped write template authorizes the `Address`/`Quantity` form and the
FC23 `WriteAddress`/`WriteQuantity` form separately, matching what the decoder
populates per function code. Keep both clauses when you substitute your own
tuples, or approved writes will alert.

The capture-loss rule is coverage evidence, not an attack signal: keep it
enabled so that a quiet result set can be told apart from a direction that
stopped decoding.

`-approved-workstations` loads an IP list for the `IsApprovedWorkstation()`
rule helper if you prefer that to inline addresses. See
[Rules Engine](RULES_ENGINE.md) and [Filtering](FILTERING.md).

## RTU Over TCP

RTU framing (unit byte, PDU, CRC16, no MBAP) is decoded only for endpoints you
name explicitly:

```bash
net capture -read gateway.pcap -out modbus-hunt -include Modbus \
  -reassemble-connections=true -payload \
  -modbus-rtu-endpoints '192.0.2.30:1502,[2001:db8::1]:502'
```

`net export` accepts the same flag; both read `NC_MODBUS_RTU_ENDPOINTS`. Values
are comma-separated `IP:port` or `[IPv6]:port` with a nonzero port; an invalid
entry fails decoder initialization. Matching is exact on the server address and
port (or the client side when no handshake was observed, since a midstream
capture may have its direction reversed) — there is no CIDR, hostname or
wildcard form, and no autodetection. Listing an endpoint takes priority over
every other decoder and disables MBAP parsing for that conversation, so do not
list an MBAP endpoint.

RTU records set `Transport == "rtu_tcp"`, `HasChecksum`, `ChecksumValid` and
`UnitID`; `HasMBAP` is false and `TransactionID`/`ProtocolID`/`Length` are zero.
Correlation is a single outstanding request per conversation, matched on
unit, function code and response shape within 30 seconds; a loss blocks it for
the remainder of the conversation. Unit-0 frames are accepted only as write
requests and the diagnostics permitted for unit 0, and are marked `Broadcast`
with `CorrelationStatus == "not_applicable"`; no response is expected. The
four-byte empty-request functions (FC7, 11, 12, 17) and FC24 are framed and
correlated here too.

Only frames that pass CRC **and** parse to a valid PDU are emitted, so
vendor-specific and unmodelled functions are still not reported as records —
but they are no longer invisible: bytes that never framed surface as
`unframed bytes discarded` or `unframed trailing bytes` loss markers.

## Manual Payload Evidence

- **Address trap:** `Address` is the zero-based wire offset within the bank the function selects. A holding register labelled `40001` commonly means `Address == 0`; vendor conventions vary. Keep coils, discrete inputs, input registers and holding registers distinct. `UnitID` is not an address. Confirm offset, width, scaling, signedness and multi-register word order against the exact device map before claiming a process meaning for any value.
- **Direction:** field values alone do not prove initiation. FC5/6/22 responses echo their requests byte for byte; `MessageRole` comes from stream direction, so it is only as reliable as the capture.
- **Payload:** byte 0 of `Payload` is the wire function code (exception bit intact); there is no MBAP header or CRC in it. Decode base64 before reading bytes. Missing payloads require reprocessing the retained PCAP with `-payload`.

For escalation, preserve the PCAP/frame references, endpoint pair, UnitID,
transaction number, decoded record, correlation status, baseline deviation and
the OT owner's assessment.

## Limitations

- **No user identity.** Modbus has no authentication; records attribute to endpoints and units only.
- **`unknown` roles.** Without an observed handshake the direction is unknown. For FC1-4 and FC20, where request and response layouts are both plausible, netcap deliberately emits only `FunctionCode` and `Bank` — no address, quantity or values. Do not count these as writes.
- **Unmatched correlation.** Correlation is per TCP connection, keyed on transaction ID with unit/function/shape checks, a 30-second window and a 1024-pending cap. Duplicate transaction IDs, saturation, or loss mark records `ambiguous`; responses whose request was not seen stay `unmatched`. Never join on transaction ID alone across connections.
- **Gaps end coverage, they do not repair it.** A `lost` marker tells you decoding stopped or resynchronised; it does not recover the missing ADUs. Everything between the marker and the next decoded record is unobserved.
- **Gateway blind spot.** A TCP-to-RTU gateway exposes only its TCP side; `UnitID` gives no visibility into the downstream serial bus or into execution.
- **Batch, not real time.** Stream records and their alerts appear at connection completion/flush, not when a command arrives.
- **Encrypted transport** requires authorized plaintext evidence elsewhere.

## Remaining Gaps

- No native serial capture and no Modbus ASCII framing — only MBAP over TCP and RTU frames carried over TCP.
- Vendor/user-defined function codes (65-72 and 100-110), any other unmodelled code, and FC43 with an MEI type other than 14 produce `ParseStatus == "unsupported"` with no structured fields; over RTU they never frame at all and surface only as loss markers.
- FC17's vendor-defined content is framed but not interpreted, and FC12 event bytes are reported as raw codes rather than decoded events.
- The rule engine's ordered correlation is one precondition grouped by exact field equality. There are no multi-step chains beyond a single earlier record, and no range-overlap join — pairing a write with a read whose span merely covers it still has to be done after export.
- Records are emitted at connection completion/flush, so hunts run on completed conversations.
- `nc_modbus` still carries only `FunctionCode` and `Exception` labels.

See [Filtering](FILTERING.md) for expression syntax and
[Industrial Control Systems](industrial-control-systems.md) for other protocols.
