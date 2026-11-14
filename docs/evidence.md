# Evidence, analyst workspace and packet subsets

Keep the input file, the netcap version, the configuration and the health files with any conclusion you draw. Together they show how the records were produced.

## Capture health

`capture -capture-evidence` is on by default. It writes `capture-manifest.json` with the input and configuration hashes, the RunID, the scope and the ingress, admission and drop counts. Kernel statistics can be `null` when unavailable, which means unknown, not zero. If a capture was partial or had decoder errors, say so in your conclusions.

| Artifact                   | What it covers                                             |
| -------------------------- | ---------------------------------------------------------- |
| `capture-manifest.json`    | Input identity, scope and capture/admission coverage       |
| `TCPReassemblyHealth.json` | TCP checksum policy and rejection counts                   |
| `FTPDataHealth.json`       | Control/data associations and exclusions                   |
| `BehaviorHealth.json`      | Detector, queue and storage state when behavior is enabled |
| `FlowExportsHealth.json`   | Flow-export stream completeness and its record-file hash   |

Which artifacts exist depends on the features you enabled. The WebUI's Investigation Evidence view lists those produced.

## Link related records

To find everything connected to the first HTTP record in a capture:

```sh
net investigate related -read analysis -type HTTP -ordinal 0
```

The ordinal is zero-based within the record file. Instead of an ordinal you can select a Connection observation ID or a content-bound ID returned by an earlier query. The API endpoint is `/api/evidence/related`.

| Relationship    | How it is found                                                             |
| --------------- | --------------------------------------------------------------------------- |
| Same connection | The Community ID and time fall inside one Connection observation            |
| Resolved by DNS | The latest matching DNS answer for the client and destination in the window |
| Rule alert      | The matched-record evidence attached to a connection                        |
| Fallback flow   | A candidate, used when no single Connection observation contains the record |

A DNS answer shortly before a connection is a candidate link. Network-detection alerts are not linked as rule alerts. Packet records and records without a usable Community ID can't all be linked.

| Scope state | Meaning                                                   |
| ----------- | --------------------------------------------------------- |
| `verified`  | One packet scope was established                          |
| `ambiguous` | Several interface/VLAN scopes. Scoped links are withheld  |
| `pending`   | The ledger isn't finalized                                |
| `overflow`  | The ledger exceeded its limit. Scoped claims are withheld |
| `missing`   | No packet-scope witness available                         |
| `legacy`    | No ledger. Relationships stay candidates                  |

Indexing is capped at one million records, 500 returned links and 64 MiB of index storage. Returned IDs are bound to file hashes and scope witnesses, so replacing or extending a file invalidates earlier references.

## Export packet evidence

To cut the packets of one conversation out of a capture, for example the DNS traffic of a single workstation, with a manifest:

```sh
net investigate packet-evidence -read office-lan.pcapng \
  -bpf 'host 192.168.1.50 and udp port 53' -out evidence.zip
```

The new ZIP contains `packets.pcapng` and `manifest.json`. The manifest lists the source and output hashes, the selection, packet ranges, interface mapping and truncation counts. Existing destinations are refused. Packet options, secrets and source statistics are not copied into the subset, so keep the original capture.

| Packet download API               | Required selection                                                         |
| --------------------------------- | -------------------------------------------------------------------------- |
| `/api/connections/download-pcap`  | `srcIP`, `srcPort`, `dstIP`, `dstPort` and `protocol=TCP` or `UDP`         |
| `/api/http/download-pcap`         | The observed endpoint ports, including non-standard ones. Transport is TCP |
| `/api/certificates/download-pcap` | Endpoint and port pairs, matched in both directions. Transport is TCP      |

All three accept paired inclusive `startNs` and `endNs` decimal strings, and `inputFile` or `sessionId` to choose the capture. Without time bounds, a tuple export includes every connection that reused the tuple, so it can contain more than one HTTP transaction or certificate occurrence.

MCP connection carving needs the observed transport, and takes `start_ns` and `end_ns` as strings to keep nanosecond precision. All four MCP carve tools accept an optional `run_id`. A stale one fails before a carve is stored.

### Split a capture

```sh
net split --read office-lan.pcapng --out subset --bpf 'host 192.168.1.50'
```

This writes `selected.pcapng` and `packet-selection.json` into a new private directory. The source is not changed, and a failed export is removed.

| Option                    | Effect                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------- |
| `--start-ns` / `--end-ns` | Inclusive time bounds, as decimal nanoseconds                                               |
| `--source-sha256`         | Refuse the split if the source content changed                                              |
| `--shard-ns 60000000000`  | Split an explicit `--start-ns`/`--end-ns` window into at most 16 disjoint inclusive windows |

Defaults are 1,000,000 selected packets, 256 MiB of output and a 1-minute deadline. A split that exceeds a limit fails instead of truncating. With `--shard-ns`, one total packet, byte and deadline budget covers all shards. `split-manifest.json` records each output's hash, its selection and the empty windows. Host and paired-connection splits use the same BPF option.

### Inspect a capture file

```sh
net split --read office-lan.pcapng --inspect
```

This prints capinfos-style JSON: the source hash and size, PCAP/PCAPNG/gzip framing, packet, captured-byte and wire-byte counts, truncation, the exact minimum and maximum Unix nanosecond timestamps, out-of-order timestamps and interfaces. Inspection reads at most 1,000,000 packets and 256 MiB of stored or decoded input within 1 minute. Unsupported, corrupt, oversized, changed or symlinked inputs fail with an error instead of a partial report. Inspection accepts gzip input, but packet export does not.

### Capture selectors and access

`sessionId` and `inputFile` must name a registered capture.

| Request                                | Result |
| -------------------------------------- | ------ |
| Unknown selector                       | 404    |
| Conflicting selectors or stale `runId` | 409    |
| Empty or duplicate selectors           | 400    |

Only requests without a selector use the active capture. One request uses one input and output context, even if the active file changes. In service mode you can read a capture only if you own it or it is a public preloaded capture. Configured MCP admin credentials keep admin access. An ID alone does not let you read another owner's private capture. The MCP backend client does not forward credentials through redirects and does not treat a 3xx body as API data.

## Reanalyze a capture

`POST /api/reanalyze` creates an `analysis-*` sibling directory and queues a separate run. The parent's audit records, extracted files, notes and completion state stay available, even if admission or the child run fails. Child jobs always record capture provenance, even when ordinary capture evidence is disabled. The child's effective capture configuration records that.

The JSON body also accepts `runId`. Body and query selectors must agree, and a stale generation cannot queue work.

| Child artifact / field      | Content                                                                                                                                                                                                                                                                                                                       |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `source/<capture-name>`     | A private copy of the input, with its SHA256 computed while copying. A known parent `inputSHA256` must match or the request returns 409. The copy uses extra disk space.                                                                                                                                                      |
| `analysis-parent.json`      | Analysis ID, creation time, engine version and commit, parent input, output and session, parent RunID and manifest SHA256 when available, source SHA256, the `whole-capture` selector, requested BPF and DPI, and a snapshot of the artifact configuration. Parent hashes that the parent capture did not record stay absent. |
| `session.json`              | In service mode, the child's owner and `parentSessionId`. A child of a public preloaded capture belongs to its requester.                                                                                                                                                                                                     |
| `/api/files/input` identity | Local children get distinct analysis IDs even when their input hashes match, so a content SHA256 alone can't identify a run.                                                                                                                                                                                                  |
| Rejected queue admission    | HTTP 503. A child that was already registered is kept as failed. The parent is untouched.                                                                                                                                                                                                                                     |

### Recovery of child analyses

On local startup, netcap rediscovers the `analysis-*` directories it owns, inside the configured output root or beside it. `analysis-state.json` keeps outcomes and timing. New children also keep the configured `analysisRoot`, so a grandchild still opens after its parent's directory is removed.

A child counts as complete only with a matching source hash, a finalized capture manifest and a matching `audit-output-ready.json`. Finished capture manifests have `status: "done"`. Queued or interrupted work shows as failed and is never rerun automatically. Missing or replaced sources show as failed children. Symlinked sources or directories, mismatched IDs and duplicate IDs are rejected. Discovery stops at 4,096 candidates and 64 MiB of metadata, and failures are logged.

The PCAP page offers whole-capture and selected-packet child analyses when the backend advertises `childAnalysisVersion: 1`. Selected children show their saved BPF and time bounds and a Parent action. If the backend does not advertise it, you can't submit this workflow.

In service mode, startup restores owned child sessions from `results/analysis-*` with their requester, parent reference, expiry and outcome. Interrupted children become failed without being requeued, and a missing or changed source can't stay ready. Child session writes are atomic, and a failed status write counts as a failure. Other sessions are not restored. An unavailable parent is never rebound to another capture.

### Reanalyze a packet subset

POST `inputFile` or `sessionId`, the expected parent `runId`, and `selection: {version: 1, sourceSHA256, bpf, startNs?, endNs?, maxPackets?, maxOutputBytes?}` to `/api/reanalyze`. Nanosecond bounds and output bytes are decimal strings. You need a BPF expression, paired inclusive bounds, or both.

The retained input is `source/selected.pcapng`. `packet-selection.json` binds the source and output hashes, the normalized selection, packet spans and counts, the interface mapping and any truncation or metadata limits. Its SHA256 is kept in `analysis-parent.json.packetManifestSHA256` and checked on recovery. In `analysis-parent.json`, `inputSHA256` identifies the derivative and `packetSelection.sourceSHA256` identifies its parent input.

| Subset limit / failure | Behavior                                                                                                                        |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Packets                | Default and maximum 1,000,000. Overflow aborts with HTTP 413                                                                    |
| Request JSON           | At most 64 KiB. Unknown fields and trailing JSON are rejected, so a misspelled selection can't silently rerun the whole capture |
| Output bytes           | Default 256 MiB, configurable up to 1 GiB. Overflow aborts with HTTP 413                                                        |
| Preparation            | 60-second timeout. Cancellation or timeout returns 408                                                                          |
| Empty / stale          | No matches returns 422. A changed source or generation returns 409                                                              |
| Failed preparation     | No job is queued, and unregistered derivative files are removed. The parent output stays intact                                 |

The MCP tool `reanalyze_session` takes `run_id`, `source_sha256`, `selection_bpf`, `start_ns`, `end_ns` and the subset limits. It checks backend support first and returns the child's identity. Polling the parent does not track child work. `get_session_info.capture_provenance` returns the parent binding. If provenance is unavailable, the error is in `capture_provenance_error`.

## Retain packets and directional streams

```sh
net capture -read suspect-host.pcap -out retained -retain-packets \
  -packet-segment-mb 32 -packet-retention-mb 512 -conns -dpi=false
```

Packet retention rotates PCAPNG segments and records expired segments as tombstones. Connection evidence writes a byte file and manifest per direction under `stream-evidence/`. TCP gaps and UDP datagram boundaries are marked. Don't concatenate a `gapped` stream and treat it as contiguous protocol input.

These options keep sensitive content and use disk. A retained subset is not the full capture. [Flow analysis](flow-analysis.md) explains whole-observation counters and estimated rates.

## Export reproduction metadata

Failed PCAP rows offer **Download reproduction metadata**. The read-only `GET /api/investigation/reproduction` takes the same capture selectors and an optional `runId`. Private sessions require ownership. Desktop exports use the failed capture's local output and a native save dialog.

Metadata is also exported for admitted captures that failed before they created `capture-manifest.json` or an output directory. In that case it keeps the admitted source SHA-256, byte count and failed-output mapping. The manifest, producer identity, RunID and effective settings are unavailable.

Unknown, conflicting, stale or unauthorized selectors are rejected, as are stale manifests and replaced source aliases. A missing manifest without an eligible admitted failure returns 404, an invalid manifest 422 and a read failure 500.

`netcap-reproduction-metadata/v1` is metadata-only. It holds the exporter version, the recorded source and configuration identity, numeric and boolean effective settings, and attachment digests and outcomes. New `capture-manifest.json` files record a `producer` when they are created: core version and commit, Go version and platform, executable VCS revision and dirty state, and module provenance when available. Captures without a `producer` entry have no producer identity. The recorded hashes are not re-checked against the source bytes.

Each attachment is reported as `digest-only`, `missing`, `read-failed` or `invalid-json`. The projected capture manifest is limited to 4 MiB, and so is each of the four optional attachments.

Source paths, raw BPF and decoder strings, logs, free-text errors and payloads are left out. Settings keep SHA256 digests. The export is not a replay bundle.

The analyst workspace previews up to 200 selected log lines from a local `.log` file of at most 4 MiB. It shows only hashes and fixed diagnostic classes, never raw text. When you approve the preview, the exact projection is stored. With `reviewedLog=true` it is exported only while the source, manifest and log digests still match. A changed or missing reviewed log fails and is never exported as an empty attachment. Nothing is uploaded and no issue is filed automatically.

## Bound analyst workspace

`/investigation-evidence` lets you include captures, search a catalogue, jump to occurrences from the table, Graph and Timeline views, save queries and reports, and review diagnostics.

`GET /api/analyst/capabilities` lists the version 1 features, limits and supported type and field paths. Clients refuse a missing version rather than fall back to the active capture. `GET /api/analyst/binding?inputFile=...` (or `sessionId`) returns the run, the recorded source SHA256 and the manifest SHA256. Finalized captures need a matching audit-ready marker. `diagnostic=true` allows failed captures for log review.

| POST endpoint              | Behavior                                                                                                                                                                                                                  |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/api/analyst/catalogue`   | `sources` lists 1 to 8 authorized captures. `query` selects by `sha256`, by case-insensitive `domain`, by IP or socket `endpoint`, or by case-sensitive allowlisted metadata `text`. You must list the supported `types`. |
| `/api/analyst/occurrences` | One bound type and at most 4,096 references. For more, narrow the catalogue query.                                                                                                                                        |
| `/api/analyst/resolve`     | Needs the exact version, type, file hash, original frame hash, ordinal, timestamp and source binding. Changed evidence returns 409. Protobuf JSON keeps integers as strings.                                              |
| `/api/analyst/inspect`     | Read-only source inspection. The input's actual hash must match the requested capture binding.                                                                                                                            |
| `/api/analyst/workspace`   | Without `document` it loads. With `document` and `expectedRevision` it saves. At most 64 documents, 16 KiB per body and 16 primary-capture references per document, and a 2 MiB private workspace written atomically.     |
| `/api/analyst/log-review`  | Previews, or approves, the same source-bound safe projection.                                                                                                                                                             |

The first source in a catalogue query is the novelty target, and later sources are the baseline. Every occurrence is kept, including duplicate frames and duplicate hashes. Each type reports its file identity, read counts and which fields were absent or partial. If an indicator field is missing, novelty is `unknown`, never "new globally". Overlapping or child captures can hold the same traffic, so occurrences are not independent events. Socket matching keeps endpoint and port pairs. `tcp://` and `udp://` need the Connection transport. Port zero and inferred transport are unsupported.

The catalogue is an on-demand scan, not a background index. Limits: 100,000 decoded records in total, 4,096 returned matches, 64 MiB stored and 128 MiB decoded per type, 4 MiB per frame, 30 seconds and 2 concurrent operations. A query that exceeds a limit fails and publishes no partial results.

The optional `page: {offset, limit}` accepts 1 to 200 matches per page. Every page after page zero needs `expectedSnapshotSHA256` from page zero. The snapshot covers all requested file identities, coverage and matches, so a changed file can't mix into a later page. The UI pages 100 items at a time and exports the complete returned catalogue with its source and coverage notes.

Saved queries keep their original `includedSources` and catalogue snapshot. Reports keep their primary-capture references and a `draft` or `reviewed` state. Review needs an unchanged saved revision and a reviewer, and any edit returns the report to draft. Revision checks and `.analyst-workspace.lock` prevent concurrent overwrites. Remove a stale lock by hand. Public preloaded captures can't have a shared writable workspace. Ownership of secondary sources is rechecked on load and save. The MCP tools expose the same typed contracts, and playbooks never approve their own reports.

In the generic Records view, **Reload current capture with exact occurrence actions** switches to `evidence=1` streaming. The selected page is published only after the complete audit file passes its integrity checks. Unfiltered views and exact Community ID views are supported. Arbitrary expression filters are not. Timeline events can also carry the same references and the complete binding with `evidence=1`, and `/api/timeline/record?reference=<JSON>` resolves one. The catalogue's table, paged graph and timeline use `/api/analyst/resolve`. The graph layout is schematic, and equal IPs in different captures are not merged into one host.

Chart HTML carries `data-netcap-coverage=v1` and an ECharts graphic that PNG and SVG exports keep. Generic charts report the prefix selection, whether the cap was reached, source counts and truncated labels. Label truncation can merge categories. Other charts report that sampling or completeness is not recorded. Protocol hierarchy links are schematic. JSON chart coverage stays machine-readable, and zero-duration buckets are rejected.
