# Related evidence and capture health

An audit record is an observation, not a complete reconstruction of a network.
Preserve the input, version, configuration and health witnesses needed to explain
how it was produced.

## Capture health

`capture -capture-evidence` is enabled by default. `capture-manifest.json` binds
input/configuration hashes, RunID, scope and ingress/admission/drop observations.
Kernel statistics can be unavailable (`null`); absence is not a measured zero.
Partial capture and decoder errors must remain visible in conclusions.

| Artifact | What it qualifies |
| --- | --- |
| `capture-manifest.json` | Input identity, scope and capture/admission coverage |
| `TCPReassemblyHealth.json` | TCP checksum policy and rejection observations |
| `FTPDataHealth.json` | Control/data associations and exclusions |
| `BehaviorHealth.json` | Scoped detector/queue/storage state when behavior is enabled |
| `FlowExportsHealth.json` | Flow-export stream completeness and its record-file hash |

Artifacts are feature-dependent. Use the WebUI's Investigation Evidence view to
inspect those actually produced.

## Link related records

```sh
net investigate related -read analysis -type HTTP -ordinal 0
```

The ordinal is zero-based in that record file. Select an existing target.
Alternative selectors include a Connection observation ID or a content-bound ID
returned by an earlier query. The API offers `/api/evidence/related`.

| Relationship | Evidence boundary |
| --- | --- |
| Same connection | Community ID and time contained in one Connection observation |
| Resolved by DNS | Latest qualifying answer for the client/destination within the window |
| Rule alert | Matched-record evidence associated with a connection |
| Fallback flow | Explicit candidate when no unique containing observation exists |

DNS temporal proximity is a candidate relationship, not proof that a lookup
caused the connection. Network-detection alerts carry different evidence and are
not automatically rule-alert links. Packet records and records without a usable
Community ID are not all linkable.

| Scope state | Meaning |
| --- | --- |
| `verified` | Unique packet scope established |
| `ambiguous` | Multiple interface/VLAN scopes; scoped links withheld |
| `pending` | Ledger not finalized |
| `overflow` | Ledger exceeded its bound; scoped claims withheld |
| `missing` | No suitable packet-scope witness |
| `legacy` | No ledger; relationships explicitly remain candidates |

Defaults bound indexing to one million records, 500 returned links and 64 MiB
accounted index storage. File hashes and scope witnesses bind returned IDs;
replacing/extending a file invalidates prior references rather than silently
rebinding them.

## Export packet evidence

```sh
net investigate packet-evidence -read traffic.pcapng \
  -bpf 'host 192.0.2.10 and udp port 9999' -out evidence.zip
```

The new ZIP contains `packets.pcapng` and `manifest.json`, including source/output
hashes, selection, packet ranges, interface mapping and truncation counts.
Existing destinations are refused. Packet options, secrets and source statistics
are not copied as if they described the selected subset; keep the original.

| Packet download API | Required tuple / time selection |
| --- | --- |
| `/api/connections/download-pcap` | `srcIP`, `srcPort`, `dstIP`, `dstPort`, and explicit `protocol=TCP` or `UDP`. |
| `/api/http/download-pcap` | The observed endpoint ports are required, including nonstandard ports; transport is TCP. |
| `/api/certificates/download-pcap` | Endpoint/port pairs are preserved in both directions; transport is TCP. |

All three accept paired inclusive `startNs`/`endNs` decimal strings and explicit
`inputFile`/`sessionId` capture selection. Without time bounds, a tuple export
includes matching reused connections and other transactions; it is not proof of
a unique HTTP transaction or certificate occurrence. HTTP exports no longer
guess ports 80/443/8080. MCP connection carving requires the observed transport;
its `start_ns`/`end_ns` fields preserve nanoseconds as strings.
All four MCP carve tools also accept optional `run_id`; a stale generation fails
before a carve is stored. Their results retain the query and tuple-reuse limitations.

`net split --read traffic.pcapng --out subset --bpf 'host 192.0.2.10'`
writes `selected.pcapng` and `packet-selection.json` into a new private directory.
Optional `--start-ns`/`--end-ns` are inclusive decimal nanoseconds;
`--source-sha256` refuses changed source content. Defaults are 1,000,000 selected
packets, 256 MiB output and a 1-minute deadline; limits fail rather than truncate.
The source stays unchanged and failed exports are removed. `--shard-ns 60000000000`
partitions an explicit `--start-ns`/`--end-ns` window into at most 16 disjoint
inclusive windows. A single total packet/byte/deadline budget applies to all shards;
`split-manifest.json` records each derivative's hash, selection and empty windows.
Repeated source scans must retain the same hash. Host/paired-connection splits use
the same BPF; no protocol guessing or automatic directory scanning occurs.

`net split --read traffic.pcapng --inspect` returns capinfos-style JSON: stored
source hash/size, PCAP/PCAPNG/gzip framing, packet/captured/wire-byte counts,
truncation, exact min/max Unix nanoseconds, out-of-order timestamps and interfaces.
Inspection defaults to 1,000,000 packets and 256 MiB stored/decoded input, with a
1-minute deadline. Unsupported, corrupt, oversized, changed or symlinked inputs
fail instead of returning a partial successful report. Gzip inspection does not
imply compressed input support for packet export.

Explicit `sessionId`/`inputFile` selectors must resolve to a registered capture;
unknown selectors return 404, conflicting selectors or stale `runId` return 409,
and empty/duplicate selectors return 400. Only requests without selectors may use
the active capture. One request keeps one input/output context across active-file
changes. Service reads require ownership or a public preloaded capture; configured
MCP admin credentials retain administrative access. IDs alone no longer grant
cross-owner private reads. The MCP backend client does not forward credentials
through redirects or treat a 3xx body as successful API data.

`POST /api/reanalyze` also accepts `runId` in its JSON body. Body and query
selectors must agree; a stale generation cannot enqueue work.

## Reanalyze a capture

`POST /api/reanalyze` creates an `analysis-*` sibling directory and a separate
queued run. Parent audit records, extracted files, notes and completion state
remain available, including when admission or child processing fails.
Child jobs require capture-provenance witnesses even when ordinary capture
evidence is disabled; their effective capture configuration records that policy.

| Child artifact / field | Contract |
| --- | --- |
| `source/<capture-name>` | Private copied input; SHA256 calculated during copying. A known parent `inputSHA256` must match or the request returns 409. The copy consumes additional disk space. |
| `analysis-parent.json` | Analysis ID, creation time, engine version/commit, parent input/output/session, available parent RunID and manifest SHA256, source SHA256, `whole-capture` selector, requested BPF/DPI and exact artifact-configuration snapshot. Missing legacy parent hashes remain absent. |
| `session.json` | Service-mode child ownership and `parentSessionId`; a child of a public preloaded capture belongs to its requester. |
| `/api/files/input` identity | Local children use distinct analysis IDs even when their input hashes match. Content SHA256 alone cannot identify a run. |
| Rejected queue admission | HTTP 503; an already registered child is retained as failed. Parent state is untouched. |

Local startup rediscovers owned `analysis-*` directories immediately inside the
configured output root or beside it, with parent relationships bound to that
root. `analysis-state.json` atomically preserves local outcomes and timing.
New children also retain the configured `analysisRoot`, allowing a retained
grandchild to reopen after its immediate parent's directory is removed.
Completion requires a matching source hash, finalized capture manifest and
matching `audit-output-ready.json`; queued/interrupted work becomes a visible
failure and is never automatically rerun. Missing/replaced sources remain visible
as failed children. Symlinked sources/directories, mismatched IDs and duplicate
IDs are rejected. Discovery is capped at 4,096 candidates and 64 MiB accounted
metadata; failures are logged.

The PCAP page offers whole-capture and selected-packet child analyses when the
backend advertises `childAnalysisVersion: 1`. Selected children show their saved
BPF/time bounds and a Parent action; unsupported backends cannot submit the new
workflow. Service startup restores owned child sessions from `results/analysis-*`
with their original requester, parent reference, expiry and outcome. Interrupted
children become failed without requeueing; missing or changed sources cannot
remain ready. Child session writes are atomic, and status persistence failures
are failures. General non-child session restoration remains disabled; an
unavailable parent is not silently rebound to another capture.

For a subset, POST `inputFile` or `sessionId`, the expected parent `runId`, and
`selection: {version: 1, sourceSHA256, bpf, startNs?, endNs?, maxPackets?,
maxOutputBytes?}` to `/api/reanalyze`. Nanosecond bounds and output bytes are
decimal strings. At least a BPF expression or paired inclusive bounds is required.
The retained input is `source/selected.pcapng`; `packet-selection.json` binds
source/output hashes, normalized selection, packet spans/counts, interface mapping
and truncation/metadata limitations; its SHA256 is retained in
`analysis-parent.json.packetManifestSHA256` and checked on recovery.
`analysis-parent.json.inputSHA256` identifies
the derivative, while `packetSelection.sourceSHA256` identifies its parent input.

| Subset limit / failure | Contract |
| --- | --- |
| Packets | Default and maximum 1,000,000; overflow aborts with HTTP 413. |
| Request JSON | At most 64 KiB; unknown fields and trailing JSON are rejected, so a misspelled selection cannot silently rerun the whole capture. |
| Output bytes | Default 256 MiB; configurable up to 1 GiB; overflow aborts with HTTP 413. |
| Preparation | 60-second timeout; cancellation/timeout returns 408. |
| Empty / stale | No matches returns 422; changed source/generation returns 409. |
| Failed preparation | No queued job; unregistered derivative files are removed. Parent output remains intact. |

MCP `reanalyze_session` exposes `run_id`, `source_sha256`, `selection_bpf`,
`start_ns`/`end_ns` and subset limits. It verifies backend support first and
returns the child identity; polling the original parent cannot track child work.
`get_session_info.capture_provenance` supplies the parent binding; unavailable
provenance is reported separately as `capture_provenance_error`.

Recovery pitfall: real capture manifests finish with `status: "done"`; the
older synthetic `"complete"` spelling is accepted only with the same hash/ready
witnesses. A completion flag alone is insufficient.

## Retain packets and directional streams

```sh
net capture -read traffic.pcap -out retained -retain-packets \
  -packet-segment-mb 32 -packet-retention-mb 512 -conns -dpi=false
```

Packet retention rotates PCAPNG segments and records expired segments as
tombstones. Connection evidence writes directional byte files and manifests under
`stream-evidence/`; TCP gaps and UDP datagram boundaries are explicit. Do not
concatenate a `gapped` stream and treat it as contiguous protocol input.

These options retain sensitive content and use disk. A bounded retained subset
is not the original complete capture. [Flow analysis](flow-analysis.md) explains
whole-observation counters and estimated rates.

## Export reproduction metadata

Failed PCAP rows offer **Download reproduction metadata**. The read-only
`GET /api/investigation/reproduction` accepts the same exact capture selectors
and optional `runId`; private sessions require ownership. A missing manifest is
404, an invalid manifest is 422 and a read failure is 500.

`netcap-reproduction-metadata/v1` is explicitly `metadata-only`: exporter version,
recorded source/configuration identity, numeric/boolean effective settings and
attachment digests/outcomes. New `capture-manifest.json` files record `producer`
at creation: core version/commit, Go/platform, executable VCS revision/dirty state
and available module provenance. Legacy producer identity remains unavailable;
the exporter version is separate. Recorded hashes do not freshly verify source
bytes. Each attachment distinguishes `digest-only`, `missing`,
`read-failed` and `invalid-json`; the projected capture manifest is bounded to
4 MiB, as is each of four optional attachments.

Source paths, raw BPF/decoder strings, logs, free-text errors and payloads are
omitted; settings retain SHA256 digests. This is not a self-contained replay
bundle. The analyst workspace previews at most 200 selected log lines from a
4 MiB regular local `.log`: only hashes and fixed diagnostic classes are exposed,
never raw text. Explicit approval stores the exact projection; `reviewedLog=true`
exports it only while the source/manifest/log digest still matches. A changed or
missing reviewed log fails; it never becomes an empty attachment. There is no
upload or automatic issue submission. `reproduction_test.go` checks sentinel secrets,
symlink confinement, missing reads, stale selectors and private ownership.

## Bound analyst workspace

`/investigation-evidence` offers explicit capture inclusion, catalogue search,
table/Graph/Timeline occurrence actions, saved queries/reports and diagnostic review.
`GET /api/analyst/capabilities` declares version 1 features, limits and supported
type/field paths. Clients refuse missing versions rather than falling back to the
active capture. `GET /api/analyst/binding?inputFile=...` (or `sessionId`) returns
the run, recorded source SHA256 and manifest SHA256; finalized captures require a
matching audit-ready marker. `diagnostic=true` permits failed captures for log review.

| POST endpoint | Contract |
| --- | --- |
| `/api/analyst/catalogue` | `sources` explicitly includes 1–8 authorized bindings; `query` selects `sha256`, exact case-insensitive `domain`, IP/socket `endpoint`, or case-sensitive allowlisted metadata `text`. `types` must be supported explicitly. |
| `/api/analyst/occurrences` | One bound type, at most 4,096 references; larger inputs require a narrower catalogue query. |
| `/api/analyst/resolve` | Exact version/type/file hash/original frame hash/ordinal/timestamp and source binding; changed evidence is 409. Protobuf JSON preserves integer strings. |
| `/api/analyst/inspect` | Read-only source inspection; the actual input hash must match the requested capture binding. |
| `/api/analyst/workspace` | Load without `document`; save with `document` and `expectedRevision`. At most 64 documents, 16 KiB body and 16 primary-capture references/document; 2 MiB private atomic workspace. |
| `/api/analyst/log-review` | Bounded preview or explicit approval of the same source-bound safe projection. |

Catalogue source zero is the novelty target; later sources are the declared baseline.
Every occurrence survives, including duplicate frames and duplicate hashes. Each
type reports file identity, read counts and absent/partial-field coverage. Missing
indicator fields make novelty `unknown`, never “new globally”. Overlapping or child
captures may represent the same traffic; occurrences are not independent events.
Socket matching keeps endpoint/port pairs; `tcp://`/`udp://` requires explicit
Connection transport. Port zero and inferred transport are unsupported.

The catalogue is a finite on-demand scan, not a global background index. Limits:
100,000 total decoded records, 4,096 returned matches, 64 MiB stored/128 MiB decoded
per type, 4 MiB/frame, 30 seconds and 2 concurrent operations. Exceeding a limit
fails without publishing partial results. Optional `page: {offset, limit}` accepts
1–200 matches/page; every page after zero requires `expectedSnapshotSHA256` from
page zero. The snapshot includes all requested file identities, coverage and
matches, so changed files cannot silently mix pages. The UI pages 100 items and
exports the complete returned catalogue with source/coverage qualifications.

Saved queries persist their original `includedSources` and catalogue snapshot.
Reports persist their primary-capture references and explicit `draft`/`reviewed`
state. Review requires an unchanged saved revision and a reviewer; edits return
to draft. Revision CAS and `.analyst-workspace.lock` prevent concurrent overwrite;
stale locks require explicit operator removal. Public preloaded captures cannot
have a shared writable workspace. Secondary source ownership is rechecked on load
and save. New MCP tools expose the same typed contracts; playbooks never approve
their own reports automatically.

Generic Records → **Reload current capture with exact occurrence actions** opts
into `evidence=1` streaming. The finite selected page is published only after the
complete audit file passes integrity checks. Unfiltered and exact Community ID
views are supported; arbitrary expression filters remain outside that bound path.
Timeline events optionally receive the same references with `evidence=1` and the
complete binding; `/api/timeline/record?reference=<JSON>` resolves it strictly.
The catalogue's table, paged graph and timeline use `/api/analyst/resolve`; graph
layout is schematic and equal IPs in different captures do not become one host.

Chart HTML carries `data-netcap-coverage=v1` and an ECharts graphic retained by
PNG/SVG exports. Generic charts declare prefix selection, cap reached, source counts
and truncated labels; label truncation can merge categories. Other legacy charts
declare unreported sampling/completeness rather than inventing full coverage.
Protocol hierarchy links remain explicitly schematic. JSON chart coverage stays
machine-readable, and zero-duration buckets are rejected.

Pitfalls: `gofmt` from an older installed toolchain rejects generic methods in the
existing MCP client; use the Go 1.27 toolchain formatter. Browser fixture loading
uses a resolved path because this package's Playwright config transpiles tests as
CommonJS. `analyst-renderer.html` is checked against the real coverage renderer by
`TestAnalystRenderedCoverageFixture`.
