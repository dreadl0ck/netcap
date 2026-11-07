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
