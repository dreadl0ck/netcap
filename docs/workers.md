# Workers and resource budgets

`net capture` runs `max(1, GOMAXPROCS)` workers by default. Use `-workers` to change that. Packets of one flow go to the same worker when a flow key exists; other packets use a fallback.

```sh
net capture -read traffic.pcap -out four-workers -workers 4 -dpi=false
```

More workers do not always give more throughput. Disk, parsing, native analyzers, input order and aggregation can each be the bottleneck. Benchmark with identical input and options, and compare the output as well as elapsed time and memory.

| Budget/default                              | Scope                                                                                                                                      |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Packet buffer: 1,000 entries                | Per worker queue                                                                                                                           |
| Writer buffer: 64 KiB                       | Per decoder writer; not total process memory                                                                                               |
| Reassembly maximum buffered size: 10 MiB    | Per stream direction; zero means unlimited                                                                                                 |
| Out-of-order page pressure thresholds: zero | Per worker/connection; unlimited unless set                                                                                                |
| Retained TCP payload: zero                  | `-max-retained-tcp-bytes` limits reader-owned payload copies across all workers; zero is unlimited.                                        |
| Retained reassembly pages: zero             | `-max-retained-reassembly-bytes` limits allocated TCP page payload and metadata across all workers; zero is unlimited.                     |
| Incremental TCP state: 64 MiB               | `-max-retained-tcp-state-bytes` counts parser storage and pool/connection credits while `-incremental-http` is enabled; zero is unlimited. |
| Encoded capture state: 32 MiB             | `-max-aggregate-state-bytes` bounds the resident Connection/Host/DeviceProfile/Service/Software/UDP/network cache and vulnerability/exploit deduplication keys, with excess state on disk; zero selects the in-memory implementation. |
| DPI automatic contexts                      | Up to 8; separate from protocol workers                                                                                                    |
| Evidence index                              | 64 MiB of accounted storage plus record and link limits                                                                                    |
| Optional packet retention                   | Default 32 MiB segments / 512 MiB retained                                                                                                 |
| Service upload                              | Default 100 MiB per file                                                                                                                   |

Out-of-order page caches are allocated lazily, so an unused cache costs 88 bytes instead of about 2 MB. Measured on Darwin/arm64 (Apple M5 Max), 3 runs at 100 ms:

| Page-cache instances | Eager, bytes/op | Lazy, bytes/op |
| -------------------- | --------------: | -------------: |
| 1                    |       2,057,561 |             88 |
| 2                    |       4,115,121 |            176 |
| 4                    |       8,230,240 |            352 |
| 8                    |      16,460,483 |            704 |

These numbers are initialization allocations, not whole-capture RSS. In-order streams allocate no out-of-order pages. The first queued segment initializes the 1,024-page cache.

Run `capture -h` for the exact option names and defaults of your build. Queue occupancy and drop counters, `capture-manifest.json`, reassembly health and behavioral health each report a different layer. A null kernel counter means the counter is unavailable, not zero.

## Limit retained TCP payload

```sh
net capture -read traffic.pcap -out bounded -workers 8 \
  -max-retained-tcp-bytes 67108864 -dpi=false
```

This allows 64 MiB across all eight workers. You can also set it with `NC_MAX_RETAINED_TCP_BYTES`. Completed connections return their reservations.

When the limit is reached, the capture stops, the CLI exits nonzero, `capture-manifest.json` gets status `error` and `audit-output-ready.json` is not written. The output is partial. `TCPReassemblyHealth.json.retainedPayload` records the limit, peak, current and rejected bytes. A current value of zero at shutdown means the storage was released.

With `-conns`, per-stream manifests mark truncated streams as `locally-truncated` and list the dropped spans as `discardedBytes` and `discardReason`. This includes streams whose raw file is empty. These omissions do not count towards network `missingBytes`.

The limit does not cover assembler pages, connection and fragment metadata, decoder caches or process RSS. The page thresholds remain per-worker controls.

## Separate reader, page and incremental-state limits

```sh
net capture -read traffic.pcap -out bounded-http -workers 4 -dpi=false \
  -incremental-http -capture-time-idle-expiry \
  -max-retained-tcp-bytes 67108864 \
  -max-retained-reassembly-bytes 67108864 \
  -max-retained-tcp-state-bytes 67108864
```

These are three separate storage limits. Together they do not add up to a 192 MiB RSS limit. Exceeding any of them aborts the capture and prevents readiness. Check `TCPReassemblyPageBudget.json`, `TCPStreamStateBudget.json` and `TCPIncrementalHealth.json` alongside the reader health. [Incremental transactions](reassembly.md#incremental-transactions) describes the HTTP/1 subset, the completion-only fallback, `-conns` retention and capture-time expiry. Other protocols keep their own completion and cache lifecycles.

## Spill aggregate audit state

`-max-aggregate-state-bytes` defaults to 33,554,432 bytes in the CLI. Connection,
Host, DeviceProfile, Service and Software state use a private SQLite scratch file. Port/SNI counters,
profile labels, contacts, service/software-flow membership and deferred-DPI samples are separate records, so an
update does not rewrite an ever-growing aggregate.

| Property | Contract |
| --- | --- |
| Cache | Encoded values, keys and 256 bytes per entry; at most 4,096 entries. `AggregateStateHealth.json` records the limit, peak, disk reads/writes, evictions and database bytes |
| Other memory | SQLite has a separate 1 MiB page cache and 16 KiB pages. Decoded output records, codec scratch and TCP reassembly are outside this limit |
| User-agent cache | `LookupUserAgent` bounds the shared HTTP/mail result cache to 1 MiB of encoded results, keys and 256 bytes per entry, with at most 4,096 entries. Eviction reparses without dropping observations; uap-go's three ARC caches are separately configured with `CacheSize: 1024` and remain outside this byte budget |
| Scratch lifecycle | `.netcap-aggregate-*.sqlite` uses mode `0600` on POSIX and the output directory's inherited ACL on Windows; normal cleanup removes it. It is not a restart/recovery log |
| Failure | Storage errors cancel capture, propagate as capture errors and prevent `audit-output-ready.json`; a failed write never falls back to discarding aggregate state |
| Configuration | `NC_MAX_AGGREGATE_STATE_BYTES`; the effective value is recorded in `capture-manifest.json.config.maxAggregateStateBytes` |

`TestAggregateSpillingPreservesCaptureAuditSets` compares all audit-record hashes
for 1,500 generated UDP flows with the in-memory path and a 2 KiB cache, using
1 and 4 workers. `TestSpilledConnectionsMatchMemoryAcrossEvictionAndTupleReuse`
also checks repeated snapshots, reused tuples and late packets.

`TestStoredHostsPreserveNativeDPI` and `TestStoredDevicesPreserveNativeDPI`
compare native-DPI snapshots with the in-memory path. Deferred samples preserve
capture timestamps, logical interfaces, tunnel scope and FCS metadata.
`TestStoredContactSamplingMatchesBoundedMemoryPolicy` checks the existing
65,536-key tracking limit and 4,096-contact sample across 67,000 distinct contacts.
Identity seeding visits one DeviceProfile at a time through `WalkDeviceProfiles`.

`TestStoredServicesPreserveRepresentativeAndFlowMembership` checks 5,000 distinct
flow references against the in-memory implementation, including banner selection
and application labels. `TestServiceProbeCanReenterAggregateStore` checks that a
service signature can emit a software lookup that accesses the same store.

| Software check | Coverage |
| --- | --- |
| `TestStoredSoftwareMatchesMemoryWithFlowChurnAndCallbacks` | 5,000 flows, duplicate observations, ordered lists, callback replacement, host/role identity and tiny-cache equivalence; hot rows contain no accumulated memberships |
| `TestStoredSoftwareConcurrentMembershipAndSnapshotIsolation` | Concurrent flow/CID updates, detached snapshots and reset |
| `TestStoredSoftwareLookupCanReenterBackingStore` | CVE callbacks run outside backing-store and row locks; lookup snapshots retain their original evidence |
| `TestStoredPassiveSoftwareDoesNotInvokeCVELookups` | SSH fingerprint observations retain their existing no-lookup policy and use the same bounded store |
| `TestAggregateSoftwarePreservesCaptureAuditSets` | All audit hashes agree for 48 HTTP transactions and 49 Software records in memory, with a 1-byte cache and with four packet workers |
| `TestAggregateSoftwareStartsFreshAcrossSequentialCaptures` | Opening a new backing store clears legacy maps and per-capture counters, including library callers that do not use CLI reset helpers |
| `TestStoredVulnerabilityDedupMatchesMemoryAndReset` / `TestStoredExploitDedupMatchesMemoryAndReset` | 5,000 host-scoped observations per type retain identical records through eviction and reset; keys use the shared cache instead of growing global sets |

`MarkSeen` atomically reserves deduplication keys before emitting a record;
callbacks run after the backing-store lock is released. With backing enabled,
vulnerability/exploit writer failures fail the store and therefore the capture.

UDP datagrams use restartable, capture-time-ordered storage. All 10 eligible
stream readers consume one datagram at a time, and stream-evidence spans are
spooled rather than accumulated in a slice. `TestStoredUDPDoesNotRetainConversationPayload`
retains 61,072 bytes of Go heap for 32 MiB of UDP payload with a 65,536-byte cache;
the backing database occupies 44,056,576 bytes. `TestAggregateUDPReplyFirstAndPayloadEvidence`
compares reply-first audits, raw conversation bytes and directional manifests
against the in-memory path. Separate datagrams are not concatenated for HTTP,
MQTT-SN or Protobuf parsing.

Network-layer conversations retain no payload state unless `-conns` is enabled.
When enabled, `TestStoredNetworkPreservesLegacyConversationBytes` checks the
restartable backing path against the legacy files. Capture time and ingress
ordinal determine ordering; metadata and directions survive repeated reads.
`TestAggregateNetworkPreservesCaptureAuditSetsAndPayloads` compares ICMPv4/ICMPv6
audits and raw conversation bytes with 1 and 4 workers. Network output errors
fail the capture and prevent readiness (`TestAggregateNetworkOutputFailurePreventsReady`).

### TCP control-state storage

With aggregate backing enabled, each assembler pool targets a 4,096-candidate
control-state cache, spilling the least-recently-used candidate. Shared-pool
assemblers can temporarily add their in-flight streams before publication.
`ControlStorageHealth` distinguishes resident controls, total resident connections
and stored controls. Ordinary payload-bearing streams are not eligible for this
control-state path.

| Contract | Implementation and check |
| --- | --- |
| Eligibility | No payload readers, incremental parser, pending FIN callback or retained reassembly pages; established control-only and closed control-only streams remain eligible |
| Recovery | Preserve network/transport/scope keys, TCP FSM, MSS/window options, sequence/ACK/FIN state, directions, first/last timestamps and capture metadata. Restore before processing a later packet; `TestColdControlsPreserveLateHandshakeAndCaptureAudits` compares every audit hash across a 5,000-flow pressure fixture |
| Lifecycle | EOF closes stored controls without allocating one pool slot per historical flow. Repeated flushes and later closed-state expiry retain their existing semantics; `TestColdTCPPoolBoundsSYNStatesAndPreservesLateControls` checks counters and retirement |
| Deadlines and sharing | Disk indexes use strict last-seen cutoffs; scope keys remain direction-independent. `TestColdTCPIdleExpiryUsesStrictRestoredLastSeen` and `TestColdTCPSharedPoolPreservesScopeAndConcurrentGenerations` run under the race detector |
| Failure | Invalid snapshots fail and cancel the backing store instead of starting a new TCP incarnation (`TestColdTCPRestoreCorruptionCancelsBackingStore`) |
| Limits | This bounds control-state residency, not active payload/parser state or RSS. TCP payload, page and incremental-state budgets remain separate. Unbudgeted pool allocation batches stop growing at 4,096 slots |

On the Linux/amd64 2-CPU, 8-GiB fixture, 200,000 SYN flows with a 1-MiB encoded
cache retained 44,090,648 bytes of Go heap at 280,322,048-byte peak RSS, taking
58.25 seconds including finalization. The database occupied 650,346,496 bytes.
The preceding matched aggregate-only spill run retained 422,654,640 bytes at
1,171,546,112-byte peak RSS in 28.25 seconds. These are synthetic resource results;
the original evaluator corpus remains unavailable.

For 200,000 generated SYN tuples, each comparison used one Linux/amd64 test
binary, 2 CPUs, an 8 GiB container and a 1 MiB encoded cache. Runtime includes
finalization; values below compare each spill mode to its matched in-memory run.

| Spill scope | Retained Go heap, bytes | Peak RSS, bytes | Runtime, seconds |
| --- | --- | --- | --- |
| Connection | 701,100,008 → 458,418,520 | 2,244,902,912 → 1,247,657,984 | 11.314 → 16.259 |
| Connection + Host + DeviceProfile | 701,017,776 → 422,588,384 | 2,318,585,856 → 1,207,033,856 | 10.715 → 26.203 |

These synthetic measurements do not close DS-12/DS-14 or qualify the unavailable
large corpus; see `internal/collector/testdata/recheck-v0166.json`.

## Operational tuning

1. Measure the input packet rate and the decoders and enrichment you need.
2. Keep a representative benign capture and its expected output counts or hashes.
3. Change one budget at a time and replay the same capture into a fresh directory.
4. Check the error, drop and completeness files and the native context statistics.
5. Test live capture separately. Reading a file does not show kernel drops, capture privileges or the behavior of a production SPAN port.

Do not disable limits or drop record types to make a benchmark look faster. [Testing](tests.md) explains how worker invariance is checked.
