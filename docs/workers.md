# Workers and resource budgets

Go v0.15.2 defaults capture workers to `max(1, GOMAXPROCS)`. Dispatch uses a
symmetric flow key where possible, with a fallback when no suitable key exists;
it is not simply round-robin for every packet.

```sh
net capture -read traffic.pcap -out four-workers -workers 4 -dpi=false
```

More workers do not guarantee more throughput: disk, parsing, native analyzers,
input locality and aggregation can dominate. Benchmark identical input/options
and compare output witnesses as well as elapsed time and memory.

| Budget/default | Scope |
| --- | --- |
| Packet buffer: 1,000 entries | Per configured worker queue |
| Writer buffer: 64 KiB | Per decoder writer, not total process memory |
| Reassembly maximum buffered size: 10 MiB | Per stream direction; zero means unlimited |
| Out-of-order page pressure thresholds: zero | Per worker/connection; unlimited unless configured, not a global RAM cap |
| Retained TCP payload: zero | `-max-retained-tcp-bytes` bounds reader-owned payload copies across all workers; zero is unlimited. |
| Retained reassembly pages: zero | `-max-retained-reassembly-bytes` caps allocated TCP page payload/metadata across all workers; zero is unlimited. |
| Incremental TCP state: 64 MiB | `-max-retained-tcp-state-bytes` accounts parser storage and pool/connection credits while `-incremental-http` is enabled; zero is unlimited. |
| DPI automatic contexts | Up to 8; distinct from protocol workers |
| Evidence index | 64 MiB accounted storage plus record/link bounds |
| Optional packet retention | Default selected budgets: 32 MiB segments / 512 MiB retained |
| Service upload | Default 100 MiB per file; not a hard global filesystem ceiling |

Out-of-order page caches allocate lazily (`internal/reassembly/memory.go`).
`BenchmarkPageCacheInitialization`, Darwin/arm64 Apple M5 Max, 3 runs at 100 ms:

| Page-cache instances | Before, bytes/op | Lazy, bytes/op |
| --- | ---: | ---: |
| 1 | 2,057,561 | 88 |
| 2 | 4,115,121 | 176 |
| 4 | 8,230,240 | 352 |
| 8 | 16,460,483 | 704 |

These are initialization allocations, not whole-capture RSS. In-order streams
allocate no out-of-order pages; the first queued segment initializes the existing
1,024-page cache. Aggregate reassembly/parser memory still needs separate bounds.

Check `capture -h` for the exact option names and installed defaults. Queue
occupancy/drop counters, `capture-manifest.json`, reassembly health and behavioral
health report different layers. A null kernel counter is unavailable, not zero.

```sh
net capture -read traffic.pcap -out bounded -workers 8 \
  -max-retained-tcp-bytes 67108864 -dpi=false
```

This configures 64 MiB across all eight workers, also available through
`NC_MAX_RETAINED_TCP_BYTES`. Completed connections return their reservations.
Exhaustion cancels collection, returns a nonzero CLI result, records
`capture-manifest.json` status `error`, and withholds `audit-output-ready.json`.
`TCPReassemblyHealth.json.retainedPayload` records the limit, peak, current and
rejected bytes; a shutdown current value of zero means released storage.

With `-conns`, per-stream manifests preserve `locally-truncated` status and quoted
`discardedBytes`/`discardReason` spans, including loss-only streams with empty raw
files. These local omissions do not increment network `missingBytes`.

The bound excludes assembler pages, connection/fragment metadata, decoder-owned
caches and process RSS. Existing page thresholds remain per-worker pressure
controls. A budget-aborted output is partial evidence, not a finalized analysis.

For separate reader, page and incremental-state caps:

```sh
net capture -read traffic.pcap -out bounded-http -workers 4 -dpi=false \
  -incremental-http -capture-time-idle-expiry \
  -max-retained-tcp-bytes 67108864 \
  -max-retained-reassembly-bytes 67108864 \
  -max-retained-tcp-state-bytes 67108864
```

These are three accounted-storage budgets, not a combined 192 MiB RSS limit.
Each exhaustion aborts capture and prevents readiness. Inspect
`TCPReassemblyPageBudget.json`, `TCPStreamStateBudget.json` and
`TCPIncrementalHealth.json` alongside the existing reader health.
[Incremental transactions](reassembly.md#incremental-transactions) documents the
observed-handshake HTTP/1 subset, completion-only fallback, `-conns` retention
and independent capture-time expiry policy. Other protocols retain their own
completion and cache lifecycles.

## Operational tuning

1. Measure the input packet rate and required decoder/enrichment set.
2. Retain a representative benign fixture and expected output counts/hashes.
3. Change one budget at a time; replay the same capture into fresh directories.
4. Inspect error/drop/completeness witnesses and native context statistics.
5. Validate live behavior separately: offline file throughput does not measure
   kernel drops, capture privileges or a production SPAN path.

Do not disable bounds or silently drop record families to produce a faster
benchmark. [Testing](tests.md) explains worker-invariance qualification.
