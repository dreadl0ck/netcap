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
| Out-of-order page limits: zero | Unlimited unless configured; not a global RAM cap |
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

## Operational tuning

1. Measure the input packet rate and required decoder/enrichment set.
2. Retain a representative benign fixture and expected output counts/hashes.
3. Change one budget at a time; replay the same capture into fresh directories.
4. Inspect error/drop/completeness witnesses and native context statistics.
5. Validate live behavior separately: offline file throughput does not measure
   kernel drops, capture privileges or a production SPAN path.

Do not disable bounds or silently drop record families to produce a faster
benchmark. [Testing](tests.md) explains worker-invariance qualification.
