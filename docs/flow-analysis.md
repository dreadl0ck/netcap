# Flow analysis

Packet-derived `Connection` observations and router-exported flow metadata are
different inputs. Choose the query engine that matches the evidence.

## Rank Connection observations

```sh
net investigate flows -read analysis/Connection.ncap.gz \
  -start-ns "$START_NS" -end-ns "$END_NS" \
  -filter 'InSubnet(SrcIP, "192.0.2.0/24")' -group-by srcIP
```

`START_NS`/`END_NS` are inclusive UTC nanosecond integers chosen for your capture.
They are not literal shell defaults. Query groups include endpoints, pairs,
ports and protocol; sorting includes bytes, packets, peers, duration and rate.
Inspect `investigate flows -h` for limits and selectors.

| Field/control | Meaning |
| --- | --- |
| `ObservationID`, `SnapshotSequence` | Reconcile cumulative Connection snapshots |
| `-window-mode overlap` | Include whole observations overlapping the window |
| `contained`, `start`, `end` | Different interval selection semantics |
| `-bucket-ns` | Optional uniformly interpolated bins, not observed per-packet timing |
| Rate | Bytes divided by summed observation durations, not necessarily window wall time |

Legacy repeated tuples without snapshot semantics can be ambiguous; the reader
does not guess deduplication or invent session counts. Defaults bound frame size,
decoded input, records, groups and query duration. Exceeded limits fail instead
of producing an unlabeled complete result. `/api/flows/query` uses the same
bounded engine.

## Collect flow exports

```sh
mkdir flow-input
net investigate collect-flows -listen 127.0.0.1:2055 -out flow-input -duration 1m
```

This opens a UDP receiver for explicitly configured exporters. It is not a packet
capture of arbitrary traffic and does not actively configure routers. Normalized
NetFlow v5/v9, IPFIX and sFlow v5 observations, raw datagrams and issue events go
to `FlowExports.jsonl`; finalized health binds its hash.

Offline packet capture can enable `-flow-exports` on configured export ports
(defaults `2055,4739,6343,9995,9996`). Existing flow-export artifacts are refused.

## Query an exporter/domain

```sh
net investigate exported-flows -read flow-input/FlowExports.jsonl \
  -exporter 192.0.2.10:50000 -format netflow-v9 -domain 7 \
  -start-ns "$START_NS" -end-ns "$END_NS" -time-basis receive
```

Replace exporter, domain, format and time bounds with actual observations.

| Constraint | Interpretation |
| --- | --- |
| Templates | Exporter/collector/domain scoped, bounded and expiring |
| Sampling | Keep reported counts; do not silently expand or mix sampling settings |
| `flow` time | Requires exported start/end times |
| `receive` time | Datagram capture/receipt time; sFlow does not establish flow start/end |
| Missing templates/sequence gaps | Issue events and partial health |
| Incomplete/cumulative counters | Excluded and counted explicitly by ranking |

Flow exports lack original packet payloads. Use [packet evidence](evidence.md)
when a claim needs bytes, and keep exporter identity and sampling context in any
report.
