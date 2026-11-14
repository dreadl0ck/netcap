# Flow analysis

Packet-derived `Connection` records and router-exported flow data (NetFlow, IPFIX, sFlow) are different inputs with different queries. Use `investigate flows` for the first and `collect-flows` plus `exported-flows` for the second.

## Rank Connection observations

This ranks the top talkers in a subnet from a capture:

```sh
net investigate flows -read analysis/Connection.ncap.gz \
  -start-ns "$START_NS" -end-ns "$END_NS" \
  -filter 'InSubnet(SrcIP, "192.168.1.0/24")' -group-by srcIP
```

`START_NS` and `END_NS` are inclusive UTC nanosecond integers that you choose for your capture. Query groups include endpoints, pairs, ports and protocol. You can sort by bytes, packets, peers, duration and rate. Run `investigate flows -h` for limits and selectors.

| Field/control                       | Meaning                                                                     |
| ----------------------------------- | --------------------------------------------------------------------------- |
| `ObservationID`, `SnapshotSequence` | Reconcile cumulative Connection snapshots                                   |
| `-window-mode overlap`              | Include whole observations that overlap the window                          |
| `contained`, `start`, `end`         | Other ways to select observations by interval                               |
| `-bucket-ns`                        | Optional bins with traffic spread evenly across them, not per-packet timing |
| Rate                                | Bytes divided by the summed observation durations, not the window length    |

Connection files with repeated tuples and no snapshot fields are ambiguous. The reader doesn't guess at deduplication or invent session counts.

Defaults limit frame size, decoded input, records, groups and query time. A query that exceeds a limit fails. `/api/flows/query` uses the same engine.

## Collect flow exports

```sh
mkdir flow-input
net investigate collect-flows -listen 127.0.0.1:2055 -out flow-input -duration 1m
```

This opens a UDP receiver for exporters you have configured to send to it. It does not capture arbitrary traffic and does not configure routers. NetFlow v5/v9, IPFIX and sFlow v5 observations, raw datagrams and issue events are written to `FlowExports.jsonl`. The finalized health file records its hash.

An offline packet capture can also decode flow exports with `-flow-exports` on the export ports (default `2055,4739,6343,9995,9996`). Existing flow-export files are refused.

## Query an exporter/domain

```sh
net investigate exported-flows -read flow-input/FlowExports.jsonl \
  -exporter 192.168.1.1:50000 -format netflow-v9 -domain 7 \
  -start-ns "$START_NS" -end-ns "$END_NS" -time-basis receive
```

Use the exporter, domain, format and time bounds from your own data.

| Topic                           | How it is handled                                                     |
| ------------------------------- | --------------------------------------------------------------------- |
| Templates                       | Kept per exporter, collector and domain. They are capped and expire   |
| Sampling                        | Reported counts are kept. Sampling settings are not expanded or mixed |
| `flow` time                     | Needs exported start and end times                                    |
| `receive` time                  | When the datagram was received. sFlow has no flow start or end        |
| Missing templates/sequence gaps | Recorded as issue events and partial health                           |
| Incomplete/cumulative counters  | Excluded from ranking, and the exclusions are counted                 |

Flow exports carry no packet payloads. Use [packet evidence](evidence.md) when you need the bytes, and record the exporter and sampling settings in any report.
