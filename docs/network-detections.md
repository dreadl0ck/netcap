# Network detections

The network-detection engine looks for patterns in packet and application traffic: scans, DNS patterns, periodic connections and large transfers, plus application policy observations. It is on by default. `-network-detection-config` takes a JSON policy file.

It works alongside YAML rules and approved behavioral baselines:

| Mechanism          | Input                                 | What it reports                            |
| ------------------ | ------------------------------------- | ------------------------------------------ |
| YAML rules         | Typed audit records                   | An expression, threshold or sequence match |
| Network detections | Packet and application observations   | A pattern, indicator or policy match       |
| Behavior           | Scoped facts and an approved baseline | A change from the state you approved       |

The alert's detector identifier, evidence and observation time tell you which mechanism produced it.

## Investigate a finding

1. Check the capture scope, gaps and admission health.
2. Read the detector's evidence, not just the alert title.
3. Compare endpoints and time with decoded transactions and connection summaries.
4. Remember that encrypted traffic shows timing and endpoints, not authentication or commands.
5. Test against benign traffic before you change a threshold or allowlist.

Some application findings are produced only after record processing finishes, so check the final output rather than a partial run.

## Application timing and bounds

| Capture mode | Application observations                                                                                                                                                                                                                                                                                                                          |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Live         | Each maintenance tick and output checkpoint drains decoded observations in capture-time order within that batch, then emits partial aggregates. Scan and beacon history survives checkpoints. A record older than the previous batch's event watermark is skipped and counted in `applicationLate`. Wall-clock time never advances the watermark. |
| Offline      | Observations are sorted by capture time at end of file, whatever the replay speed.                                                                                                                                                                                                                                                                |

All workers share one observation queue, limited to 16 MiB and 100,000 records, including a checkpoint batch being processed. `NetworkDetectionStats.json` reports `applicationQueueLimit`, `applicationQueuedBytes`, `applicationPeakBytes` and `applicationQueueDrops`. When the queue overflows, observations are dropped, so check `applicationQueueDrops` before you conclude that no scanning or beaconing happened.

`-incremental-http` emits HTTP/1 transactions from qualified open keep-alive connections, so live checkpoints process them before shutdown. Other protocols, TCP streams with uncertain roles and deferred upgrade tails are decoded at completion. See [TCP reassembly](reassembly.md#incremental-transactions) for eligibility, budgets and finalization. Transactions emitted at these boundaries do not count as complete transactions for `http.scan` or `c2.beacon`.

## Indicators and policy

Start from the minimal example [`docs/examples/network-detection.json`](examples/network-detection.json). Omitted thresholds take the loader's defaults, and unknown keys are rejected. Times are integer Unix nanoseconds, not seconds.

The example's indicator is a placeholder. Replace it with your own: a domain or IP from a threat report or a sinkhole feed, with its source, version and the capture-time window in which it is valid. Don't remove those fields to make an expired indicator look current. Netcap ships no threat-intelligence feed and does not ingest STIX/TAXII.

```sh
net capture -read office-lan.pcap -out policy-audit \
  -network-detection-config network-detection.json \
  -dpi=false -geoDB=false
```

The [JSON config types](https://github.com/dreadl0ck/netcap/blob/v0.15.2/internal/networkdetect/config.go) define the thresholds, approved sources and IP/domain indicators.

The WebUI's Alerts view shows the available evidence. [Related-record linking](evidence.md) does not treat these alerts as YAML-rule matches. [Behavioral monitoring](behavioral-monitoring.md) has its own learning and approval lifecycle.
