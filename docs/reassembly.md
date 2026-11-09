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

The current `-max-stream-bytes` default is 100 MiB per direction, matching the
default extracted-file limit (`internal/decoder/config/config.go`); v0.16.2 used
10 MiB. Zero-valued page limits can mean unlimited; [resource budgets](workers.md)
are not a global memory guarantee. Inspect installed help and health sidecars.

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
extraction before closing directional readers. Production readers retain fragments
synchronously, without per-direction drain channels/goroutines. Raw references
are released and slots reused (`internal/decoder/stream/tcp/tcp_resources.go`); lifetime
byte counters and any retained closed-connection FSM metadata remain available.
This releases completed-stream state during capture, without claiming a global
bound on still-open streams or decoder-owned caches.
`KeepFrom` pages previously survived half-connection closure; closure now releases
both saved/queued lists and clears delivery scratch references
(`internal/reassembly/page_budget_test.go`).
Go v0.16.2 also releases queued `KeepFrom` pages after scatter/gather cleanup
when a stream byte limit closes a direction, fixing the Brazil replay assembler
panic (`internal/reassembly/assembler.go`). Discarded bytes remain missing;
cleanup does not make truncated stream evidence complete.

`TCPReassemblyHealth.json` reports overlap packet/byte counts. Network detection
also compares retransmissions against a bounded 4,096-byte directional prefix;
different bytes produce `tcp.overlap-conflict` with qualified first-arrival
semantics. FIN/RST retains that prefix until the detection window expires or a
new SYN replaces the session; closed flows cannot resume protocol detection.
Matching retransmissions do not produce this alert (`networkdetect/recheck_test.go`).

HTTP headers cannot be completed across a TCP close. If a complete pre-close
header frames contiguous body bytes observed after closure, extraction can retain
an explicitly incomplete artifact without emitting an ordinary cross-close HTTP
transaction (`http/artifact_recovery.go`). Failed gzip integrity can preserve a
decoded-prefix child linked by `ParentFileID` to the retained wire artifact.

## Recheck qualification

`scripts/recheck-mta.py` replays checksum-pinned MTA receipts, reads every audit,
and compares extracted SHA256 sets against a matched baseline. The local
`b866b61-followup` candidate uses `nodpi,noyara,nomagika` unless noted below.

| Check | Result / evidence |
| --- | --- |
| MTA replay, Darwin/arm64, Go 1.27.0 | 143/143 successful; no unreadable audits or missing baseline artifact hashes (`mta-qualified-followup/summary.json`) |
| HTTP request comparison | 33,931 tshark requests; 0 missing; 34,422 netcap records, including 491 comparison extras (`mta-qualified-followup/reference-summary.json`) |
| Host/user scorer | 98 `ok`, 2 `wrong`, 8 unhandled; 0 baseline regressions. Both `wrong` rows expect the nonliteral label `all 3` (`mta-qualified-followup/questions-summary.json`). This is not the full question/fact score. |
| Sequential capture time | 171.49 s candidate / 145.14 s v0.15.2, same config databases; median per-capture ratio 1.036×, aggregate ratio 1.182×. V-6 remains open. |
| IoT-23 1-1, Linux/amd64, Go 1.27.1 | Final nodpi/YARA-enabled archive completes with default settings at a 4 GiB container limit: 184.7 s, 1,686,291/1,686,291 packets admitted, 0 queue drops, 21/21 audits readable, all 46 baseline file hashes retained (`iot23-final-archive/`). |
| FTP size regression | Default CLI extracts all 27,888,036 bytes with matching stored/audit SHA256 at 1/4 workers (`tests/e2e/large_ftp_test.go`); the original FOR572 capture remains unqualified. |
| FKIE C2 captures | 67/67 successful; 1,224 tshark HTTP requests, 0 missing, including the embedded-key FormBook capture (`fkie-followup/`). |
| Injection captures | 14/14 successful with qualified overlap/SYN-ACK conflict alerts; retransmission, expiry and new-session negative controls pass (`injection-closed-fixed/`, `networkdetect/recheck_test.go`). |
| HTTP polling | The 2025-06-13 capture emits 2 `c2.beacon` incidents after fitting skipped POST polls; fit requires 2 direct intervals, at most 8 cycles per gap and bounded phase error. Irregular timing, Range transfers and GET fitting are negative controls (`mta-cadence-qualification/`, `networkdetect/recheck_test.go`). |
| PCAP-ATTACK | 26/26 successful; 6 qualified observations across Netlogon bursts, remote service control, Kerberos user diversity and printer notification (`attack-qualified-followup/`). Missing interface binds/encrypted payloads remain visibility limits. |
| CTU-13 scenario 5 | 219 tshark HTTP requests, 0 missing (`ctu5-followup/`); responder-originated requests survive the binary preface. |
| SSH/CVE false positives | IoT-23 3-1 emits 0 `ssh.nonstandard-port` alerts; Nitroba emits 0 of the 3 reported CVEs against Apache 1.3.37, with 0 duplicate host/product/version/CVE tuples (`iot23-3-followup/`, `nitroba-followup/`). |
| Native archives | Fresh glibc/musl × DPI/nodpi binaries execute through symlinked launchers in clean Alpine 3.24.4; each emits 1 HTTP/1 and 2 HTTP/2 records from the upstream h2c fixture. Runtime inventories verify 17/11/9/4 supplier-matched libraries (`qualification/followup-*`). Builds use `nomagika`; native YARA tests pass. |

The IoT-23 source is `CTU-IoT-Malware-Capture-1-1/2018-05-09-192.168.100.103.pcap`
under `https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/`;
SHA256 `8ebcd17af4e2d20b1cf7ad564760756f457a80b791a0757a2b1a624b2724969c`.
The Linux capture runs use 4 CPUs, 4 workers, no network, and a 4 GiB memory/swap
cap under amd64 emulation. The CLI sets Go's soft memory limit to 75% of the
smallest visible cgroup memory limit unless `GOMEMLIMIT` or an existing runtime
limit overrides it (`internal/runtimebudget/memory.go`); manifests record
`producer.goMemoryLimitBytes`. The pre-headroom binary was OOM-killed at 4 GiB.
This controls GC headroom, not decoder-state cardinality: the remaining large
Phase B captures and external Magika classification remain unqualified.
This replay retains 620,639 Connection and 602,818 Host records; heap profiling
identifies connection/host accumulators, stream-pool entries and UDP flow state
as DS-12 follow-ups (`iot23-heap.pprof`).

| External fixture source | Pin |
| --- | --- |
| [FKIE malware C2](https://github.com/fkie-cad/malware_c2_dataset) | Revision `324d555e57161275abf3d5f910b74f40f56ca94c`; `dataset.zip` SHA256 `ba39c32b2ccb74bf37cf43ca061b7e802e5fe499b59144fc971e6a5c82c9b912`; only `.pcapng` members extracted |
| [Fox-IT Quantum Insert](https://github.com/fox-it/quantuminsert) | Revision `7b54983bdd3e33ce943e27f5772e010f08606481`, 7 captures under `pcaps/` |
| [HoneyBadger/Netresec](https://github.com/david415/honeybadger-pcap-files) | Revision `f74e56078bbf3244d9713df44ed47879ddca522a`, 4 root captures and 3 under `netresec/` |
| [PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK) | Revision `9ef5476dd6b083f565a1b9d2e59e4a3ae8be8c95`, 26 captures |
| [Suricata h2c](https://github.com/OISF/suricata-verify/tree/9a9178a7e4d45ff1d990e8f178c1e2f54b772f39/tests/http2-h2c-doh2-force-proto-change) | `input.pcap` SHA256 `92df1f0a385252357739989381269322fd1de80867f5f4d4d74da8703b711673` |
| [IoT-23 3-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/2018-05-21_capture.pcap) | SHA256 `c674dc0c8d584fa66e6f00c60df973c5fbacad551c850a76d75ec9952641d00b` |
| [Nitroba](https://for572.com/nitrobapcap) | SHA256 `f783d89ee1f6862a10e34923fb16165fdcc85811036a5a3f2a79fed8f019484a` |

Use `scripts/recheck-mta.py --inputs <directory> --group <name> --binary <net>
--output <new-directory>` for external captures; it records per-file SHA256
receipts. `--resume` requires the same binary and capture checksums and preserves
interrupted outputs separately. The 4,695-file Phase B inventory and original
answer/OCR corpus are required to reproduce the report's full score exactly.
`TestReassemblyPageBudgetCLI` builds an untagged native CLI; its 12 cases pass in
the matched Linux builder. Local older YARA-X headers fail on
`C.yrx_compiler_max_warnings` before the test runs (`recheck-native-page-e2e.log`).

Inventory pitfall: the report's 148 MTA PCAPs resolve to 143 upstream captures;
`2016-07-07` publishes 1 PCAP and 6 malicious emails, rather than 6 PCAPs.

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
