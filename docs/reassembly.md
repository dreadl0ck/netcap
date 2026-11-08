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
expiry by default. `-capture-time-idle-expiry` / `NC_CAPTURE_TIME_IDLE_EXPIRY`
opts into one-second capture-time maintenance, ordered before the packet that
advances the watermark. The watermark is the maximum observed packet timestamp;
late packets never rewind it. Both directions must be idle before expiry, and
EOF flushes the remaining state. `CaptureTimeMaintenance.json` records policy,
quoted `watermarkNs` and `latePackets`. Replay pauses and worker count do not
change these timeout decisions (`internal/collector/capture_time_test.go`).

Completed TCP connections finish decoding, conversation persistence and banner
extraction before closing/joining both reader tasks. Raw fragment/decoder references
are released and reader-registry slots reused (`tcp/tcp_resources.go`); lifetime
byte counters and any retained closed-connection FSM metadata remain available.
This releases completed-stream state during capture, without claiming a global
bound on still-open streams or decoder-owned caches.
`KeepFrom` pages previously survived half-connection closure; closure now releases
both saved/queued lists and clears delivery scratch references
(`internal/reassembly/page_budget_test.go`).

## Incremental transactions

`-incremental-http` / `NC_INCREMENTAL_HTTP` opts HTTP/1 into transaction-time
decoding. A completed keepalive transaction can produce an HTTP record and an
application alert while its TCP connection remains open. The native CLI and
collector API tests exercise 40 requests on one still-open connection at 1/4
workers (`tests/e2e/incremental_http_test.go`,
`internal/collector/incremental_http_test.go`). The default remains completion
decoding; the opt-in is propagated into service collectors and manifests.

| Input / condition | Incremental contract |
| --- | --- |
| Observed SYN handshake, unambiguous direction, HTTP/1 header within `64 KiB` | Normal decoder selection remains authoritative, including IPP specialization. Selected HTTP/1 uses `core.IncrementalFactory`; other selected decoders remain completion-only. |
| Fixed-length/chunked requests and responses, pipelining, HEAD, interim 1xx | Directional framing spans arbitrary deliveries. Each completed transaction is decoded once; interim responses stay with the final response. Chunk/trailer framing is validated without extraction side effects before accepting the next boundary. |
| Close-delimited response | Waits for finalization. Without an observed server FIN, `response-end-not-observed` preserves the missing end witness. |
| Gap or local discard | Flush the qualified partial tail, reset framing, and retain known/unknown loss counts and local-discard reasons for delegated extraction. Bytes and requests cannot join across the hole. Later loss does not retroactively rewrite an already emitted complete transaction; final health retains the loss. |
| Malformed/ambiguous framing | The affected tail waits for the evidence parser at finalization; bytes after an untrusted boundary cannot become clean incremental transactions. |
| CONNECT, Upgrade or 101 after HTTP/1 | The bounded remaining tail is completion-only, including existing HTTP/2 and TLS-upgrade inspection. Retired HTTP/1 prefixes are not replayed. |
| HTTP/2 preface, missing handshake, uncertain roles, other protocols | Existing completion decoding. `TCPIncrementalHealth.json` publishes support boundaries, selected completion-only decoder counts, incremental transaction counts, gap resets and deferred tails. |

`core.IncrementalDecoder.Push` borrows its input only during the call; retained
parser bytes are copied under the shared state budget. `Finish` receives the
completion reason and observed directional FINs; `Abort` releases state without
interpreting omitted bytes as EOF. Both are idempotent. See
`internal/decoder/core/incremental.go` and HTTP segmentation/corruption tests in
`internal/decoder/stream/http/incremental_test.go`.

Without `-conns`, completed parser storage and TCP reader prefixes retire during
capture; only the bounded initial service banner remains in the reader. With
`-conns`, records still emit incrementally but full raw conversation retention
continues under `-max-retained-tcp-bytes`. Whole-conversation generic harvesters
are not replayed over retired prefixes; HTTP's own extraction/identity/software
paths still run per transaction, and deferred upgrades retain their inspectors.

The HTTP/1 parser limits accounted working state to `8 MiB` per connection,
headers/trailers to `64 KiB` each, chunk lines to `8 KiB`, and pending requests
to `1,024`. `-max-retained-tcp-state-bytes` /
`NC_MAX_RETAINED_TCP_STATE_BYTES` adds a shared `64 MiB` default while the opt-in
is enabled; `0` is unlimited and negative values fail. It charges owned parser
buffers/bookkeeping, transaction working reservations, reusable reassembly pool
slots and fixed connection credits across all workers. Pool slots allocate one
at a time; retained closed FSMs keep their connection credit until retirement.
`TCPStreamStateBudget.json` records current/peak/rejected bytes and exhaustion.
Exhaustion cancels capture, records manifest status `error`, and prevents audit
readiness. `MaxStreamBytes` remains a separate lifetime byte limit; setting it
to `0` does not disable these parser/state budgets.

The state accounting excludes downstream writer queues, decoder/enrichment
caches, native memory and allocator/GC overhead. Credits are not an RSS limit.
Failed HTTP writes propagate through the incremental lifecycle into cancellation
and manifest failure (`TestIncrementalHTTPWriteFailurePreventsReadiness`).
Pool reuse must create the stream factory before waiting for a retired slot's
lock (`TestConnectionReuseDoesNotHoldPoolMutex`); reversing that order deadlocks
callback-ordered callers.

## Shared retention budgets

| Control | Accounted storage / exhaustion |
| --- | --- |
| `-max-retained-tcp-bytes` / `NC_MAX_RETAINED_TCP_BYTES` | Copied TCP reader payload across every worker; exhaustion aborts capture. |
| `-max-retained-reassembly-bytes` / `NC_MAX_RETAINED_REASSEMBLY_BYTES` | TCP page payload arrays plus fixed page metadata across every worker. Reservations precede allocation, multi-page requests are atomic, and consumed pages leave no free-page cache. Exhaustion aborts capture. |
| `-max-retained-tcp-state-bytes` / `NC_MAX_RETAINED_TCP_STATE_BYTES` | With `-incremental-http`, shared parser storage/working reservations and pool/connection credits; exhaustion aborts capture. |
| `-max-buffered-pages-total` | Per-worker pressure threshold; it can force gap delivery and is not an aggregate byte cap. |

Reader/page byte controls default to `0` (unlimited); the incremental state
control defaults to `64 MiB`. All reject negative values.
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
