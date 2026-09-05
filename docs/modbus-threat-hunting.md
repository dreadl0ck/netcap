# Modbus Threat Hunting

Use Netcap for passive Modbus TCP inventory and coarse function-code triage,
then validate candidates against the original capture and the site's register
map. A matching record is not proof of an unauthorized command or process change.

## Capture Safely

1. Agree scope with OT operations: approved hosts, PLCs/gateways, maintenance windows, capture duration and evidence handling.
2. Collect both directions from an approved TAP/SPAN point, without probing, replaying traffic or issuing test writes/diagnostics. Preserve the original PCAP, capture-point details, clock reference and packet-loss statistics.
3. Analyze a copy offline. Retain payloads only under the site's data-handling policy; they can expose process data and settings.

With `net` installed, substitute your capture path and a fresh output directory:

```bash
net capture -read plant.pcap -out modbus-hunt -include Modbus -reassemble-connections=true -payload -compress=true
net dump -read modbus-hunt/Modbus.ncap.gz -json
```

`Modbus` is the TCP stream decoder and audit-record name. TCP/502 is conventional,
not required: MBAP/function signatures support port-independent detection.
Do not restrict collection to port 502 if nonstandard-port use is in scope.
Signature detection is not a completeness guarantee; missing bytes, partial
captures and unsupported traffic can leave gaps. No records does not prove no
Modbus activity. These commands analyze a file, not a live controller.

The decoder frames each TCP direction independently and timestamps an ADU from
its first captured byte. A gap (including unknown initial loss), invalid MBAP
header, or fragment without accessible loss metadata stops decoding that
direction for the rest of the conversation; the opposite direction can continue.
Incomplete trailing ADUs are not emitted. There is no loss-status audit field
yet. Stream records are emitted at connection completion/flush, not immediately
when a command arrives.

## Current Fields

The current `Modbus` schema in `netcap.proto` contains:

| Fields | Practical use and limit |
| --- | --- |
| `Timestamp` | Integer Unix nanoseconds in the protobuf record; check capture timing before time-window comparisons. |
| `SrcIP`, `DstIP`, `SrcPort`, `DstPort` | Network endpoints, not authenticated identities or proof of client/server roles. |
| `CommunityID` | Flow identifier, not an application transaction or request/response classification. |
| `TransactionID` | MBAP transaction number; reusable, not globally unique. No automatic request/response correlation is provided. |
| `ProtocolID`, `Length`, `UnitID` | MBAP metadata. Length includes the unit byte and PDU; UnitID identifies a unit behind an endpoint, not a user. |
| `FunctionCode`, `Exception` | Function code with the exception bit removed, plus a separate exception flag. |
| `Payload` | Optional raw PDU, including its function byte, when captured with `-payload`; JSON represents bytes as base64. |

There are **no structured register/coil addresses, quantities, ranges, values,
diagnostic subfunctions, MEI types, device-ID objects or exception codes**.
There is also no request/response field. Classic Modbus has no protocol user
identity or authentication: an IP allowlist expresses expected equipment, not
which person authorized an operation. Use workstation, access and change logs
for attribution.

## Scoped Baseline And Triage

Build a known-good baseline for each cell/process, endpoint pair and UnitID,
covering routine polling, startup/shutdown and approved maintenance. Record
expected function codes, observed message volume and operating windows; get OT
owners to confirm exceptions. Compare like capture durations and visibility.
Do not treat one plant-wide allowlist or threshold as a process baseline.

Example filters use current fields only. Replace `192.0.2.20` and UnitID `1`
with the scoped PLC/gateway and unit. Include both endpoint directions:

```bash
# Write-related messages for one asset/unit, including replies and exceptions
net dump -read modbus-hunt/Modbus.ncap.gz -json -filter '(SrcIP == "192.0.2.20" || DstIP == "192.0.2.20") && UnitID == 1 && FunctionCode in [5, 6, 15, 16, 21, 22, 23]'

# Write candidates toward that asset from outside its approved-master baseline
net dump -read modbus-hunt/Modbus.ncap.gz -json -filter 'DstIP == "192.0.2.20" && UnitID == 1 && FunctionCode in [5, 6, 15, 16, 21, 22, 23] && !(SrcIP in ["192.0.2.10", "192.0.2.11"])'

# Diagnostics and encapsulated-interface candidates across the capture
net dump -read modbus-hunt/Modbus.ncap.gz -json -filter 'FunctionCode in [8, 43]'

# Exception messages; inspect payload for the actual exception code
net dump -read modbus-hunt/Modbus.ncap.gz -json -filter 'Exception'
```

| Decimal function codes | Triage question |
| --- | --- |
| 1, 2, 3, 4 | Is polling from an unexpected peer, unusually broad across assets/units, or outside the scoped baseline? Read codes alone do not reveal address coverage. |
| 5, 6, 15, 16 | Are single/multiple coil or register writes expected for this asset and maintenance window? |
| 21, 22, 23 | Is file-record writing, mask writing, or combined register read/write expected? FC23 is not read-only. |
| 8 | Which diagnostic subfunction is present, and is it approved? |
| 43 | Is the MEI type 14 device-identification operation, or something else? |

Treat counts as **observed messages**, never request-only counts or successful
writes. Normal replies share function codes; FC5/FC6 write replies echo the
request and FC22 also echoes its fields. Function-only matches cannot distinguish
write echoes, even with corrected source/destination endpoints, especially in
partial captures where initiator evidence is missing. `!Exception` includes both
requests and normal replies; it is not a success or request predicate. An unusual
peer or burst is a review lead, not by itself an attack.

The example master list applies only to this destination/unit. Confirm controller
roles from inventory and the capture before interpreting the directional query.
Observed peers are baseline candidates, not automatically authorized masters.
Record approved banks, wire ranges and functions as well; the current query
cannot enforce ranges or detect an approved master writing outside them.

## Manual Payload Evidence

Use the original PCAP and a protocol-aware viewer to establish direction, TCP
stream boundaries and complete PDUs. Decode the JSON payload's base64 before
reading bytes. PDU byte 0 is the wire function code; there is no MBAP header in
`Payload`. Check lengths and exception status before interpreting the body.
Missing payloads require reprocessing the retained PCAP with `-payload`.

- **Address trap:** wire addresses are zero-based offsets within a function-selected table. A holding register labelled `40001` commonly means offset `0`, not wire address `40001`; vendor conventions vary. Keep coils, discrete inputs, input registers and holding registers distinct. UnitID is not a register address. Confirm offset, width, scaling, signedness and multi-register word order with the exact device map.
- **Writes:** after identifying a request manually, inspect its address, quantity and value bytes using that function's layout. For example, FC6 PDU `06 00 00 00 01` contains offset `0` and value `1`, but identical bytes can be its normal echo reply. Payload alone does not prove initiation, authorization or physical effect; verify with process/change records.
- **Diagnostics FC8 (`0x08`):** the next two bytes are the big-endian subfunction. Distinguish return-query-data (`0x0000`) from restart communications (`0x0001`), force listen-only (`0x0004`) and clear counters/diagnostic register (`0x000A`). Their presence warrants device-specific review, not a claim that disruption occurred. These diagnostics are serial-line-oriented; TCP gateways/devices vary in support. Never issue them to validate a finding on production equipment.
- **Discovery FC43 (`0x2B`):** inspect the next byte for MEI type `0x0E` (decimal 14, Read Device Identification). FC43 alone does not establish device discovery. Examine the request's read-device-ID code/object ID and the response's object list manually; inventory tools can legitimately enumerate identity data. Netcap does not extract vendor/product/revision fields.
- **Exceptions:** a wire function such as `0x86` becomes `FunctionCode == 6` with `Exception == true`; the next PDU byte is the exception code. Inspect it manually. An exception is not a completed write, and absence of an exception does not establish execution.

For escalation, preserve the PCAP/frame references, endpoint pair, UnitID,
transaction number, raw PDU, decoded interpretation, baseline deviation and OT
owner's assessment. Pair requests and replies manually within the same TCP
connection and capture interval; do not join on transaction number alone.

## RTU And Other Blind Spots

This workflow supports **Modbus TCP with MBAP framing**, not native Modbus RTU
serial frames, CRC checking, serial timing, or RTU-over-TCP without MBAP. A
TCP-to-RTU gateway exposes only its TCP side here; UnitID does not establish
visibility into the serial bus or downstream execution. Use an approved passive
serial capture method and a separate RTU decoder when serial evidence is needed.
Encrypted transport likewise requires authorized plaintext evidence elsewhere.

## Future Enhancements

Not available today:

- [ ] Explicit request/response/unknown classification and transaction correlation.
- [ ] Structured addresses, quantities, ranges and values with function-specific validation.
- [ ] Diagnostic subfunctions, MEI/device-ID objects and exception-code fields.
- [ ] Native RTU framing/CRC and explicit RTU-over-TCP support.

See [Filtering](FILTERING.md) for expression syntax and
[Industrial Control Systems](industrial-control-systems.md) for other protocols.
