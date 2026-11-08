# TCP reassembly

Application messages can span TCP segments, share one segment or arrive with
retransmissions/out-of-order delivery. Netcap assembles directional streams
before protocol-specific parsing; a packet boundary is not an HTTP/DNP3/Modbus
message boundary.

```sh
net capture -read traffic.pcap -out streams -reassemble-connections=true \
  -conns -dpi=false
```

## Boundaries and missing bytes

| Condition | Consequence |
| --- | --- |
| Missing SYN/initial payload | Direction/boundary can be uncertain; inspect parser-specific states |
| Known-size gap | A parser may have a restricted resynchronization rule |
| Unknown-size gap | Parsing may stop rather than guess framing |
| Retransmission | Reassembly suppresses/reconciles bytes according to its policy |
| Per-direction buffer limit | Evidence can be incomplete when bounds are reached |
| Connection finalization | Stream records and alerts may only become visible on completion/flush |
| Reader payload-budget exhaustion | Capture aborts; stream evidence labels local discards separately from network sequence gaps. |

Fallback decoder probing uses `DataFragments.ContiguousBytes()`: deliveries can
complete a header only within one observed byte run. Known and unknown gaps
cannot join partial signatures into a protocol match. A leading midstream marker
still permits probing the first observed run; it does not establish completeness.

Go v0.15.2's default maximum buffered size is 10 MiB per direction. Zero-valued
page limits can mean unlimited; [resource budgets](workers.md) are not a global
memory guarantee. Use the installed help and health sidecars for actual policy.

Live collection sends ordered maintenance to every worker once per second,
including when no new packets arrive (`internal/collector/live_maintenance.go`).
`-live-maintenance-interval` (`NC_LIVE_MAINTENANCE_INTERVAL`) overrides that interval; a negative
value disables it. Both directions must be older than `CloseInactiveTimeOut`
before an open stream expires. Pending bytes are delivered with gap evidence,
and timeout closure is labeled `idle-expired`.

| Maintenance | Time basis / effect |
| --- | --- |
| Pending-byte deadline | `FlushOptions.T` releases old sequence heads with gap evidence. |
| Closed-state retention | `FlushOptions.TC` removes retained closed connections. |
| Live idle expiry | Explicit `FlushOptions.TI` closes idle open connections; zero disables it. An opt-in deadline index avoids scanning every active stream. |
| Output snapshots | `-live-flush-interval` (`NC_LIVE_FLUSH_INTERVAL`) flushes writers/current records; zero disables snapshots. It does not expire streams. |

Offline collection does not start a wall-clock maintenance timer or enable idle
expiry; its existing packet-driven capture-time policy is preserved.

Completed TCP connections finish decoding, conversation persistence and banner
extraction before closing/joining both reader tasks. Raw fragment/decoder references
are released and reader-registry slots reused (`tcp/tcp_resources.go`); lifetime
byte counters and any retained closed-connection FSM metadata remain available.
This releases completed-stream state during capture, without claiming a global
bound on still-open streams or decoder-owned caches.
`KeepFrom` pages previously survived half-connection closure; closure now releases
both saved/queued lists and clears delivery scratch references
(`internal/reassembly/page_budget_test.go`).

## Shared retention budgets

| Control | Accounted storage / exhaustion |
| --- | --- |
| `-max-retained-tcp-bytes` / `NC_MAX_RETAINED_TCP_BYTES` | Copied TCP reader payload across every worker; exhaustion aborts capture. |
| `-max-retained-reassembly-bytes` / `NC_MAX_RETAINED_REASSEMBLY_BYTES` | TCP page payload arrays plus fixed page metadata across every worker. Reservations precede allocation, multi-page requests are atomic, and consumed pages leave no free-page cache. Exhaustion aborts capture. |
| `-max-buffered-pages-total` | Per-worker pressure threshold; it can force gap delivery and is not an aggregate byte cap. |

Both byte controls default to `0` (unlimited) and reject negative values.
`TCPReassemblyPageBudget.json` records the page limit, current/peak bytes,
rejected allocation bytes and exhaustion. `capture-manifest.json` records
`maxRetainedReassemblyBytes` as a quoted integer; budget failure produces status
`error` and no audit-ready marker. Stream spans retain actual discarded payload
bytes with reason `tcp-reassembly-page-budget` and status `locally-truncated`.
Rejected allocation bytes include page metadata/padding and therefore need not
equal discarded payload bytes.

These controls exclude connection metadata, packet contexts, protocol parser
copies, decoder caches, native libraries and Go garbage awaiting collection.
Neither configured byte limits nor `0` certify process RSS. Tests:
`internal/collector/page_budget_test.go`, `tests/e2e/page_budget_test.go`.

## Inspect the evidence

With `-conns`, `stream-evidence/stream-*/` contains `client.bin`, `server.bin`
and a manifest recording direction, offsets, times, gaps and UDP boundaries where
applicable. The display transcript is separate. Never remove gap markers and
pass concatenated bytes to an experiment as if they were contiguous.

Protocol parsers differ. Modbus stops or resynchronizes only at defined points;
DNP3 CRC/framing evidence and HTTP recovery have their own limits. Read the
protocol-specific guide before interpreting `lost`, `unmatched` or a recovered
record as complete coverage.

The HTTP API/view exposes `reassemblyStatus` and string-valued `timestampNs`.
Empty reassembly status does not establish completeness; missing capture time
stays unavailable. Generic numeric JSON timestamps are not relabeled as exact
nanoseconds (`cmd/capture/webui/audit_semantics_test.go`).

`TCPReassemblyHealth.json` qualifies checksum policy and rejections. Malformed
input, encrypted payloads and unsupported protocols can all yield no application
records. [Capture health](evidence.md) helps distinguish missing visibility from
an observed negative.
