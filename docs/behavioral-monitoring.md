# Behavioral monitoring

Behavior observes sensor/interface/VLAN-scoped device facts, service edges and
traffic models. It is opt-in: learning is not approval, and new observations do
not silently become trusted baseline facts.

```sh
net capture -read traffic.pcap -out behavior-audit -behavior \
  -http 127.0.0.1:8080 -dpi=false
```

Open the Behavior view. Short PCAPs may not meet default learning requirements:
seven days of capture-time coverage and 100 observations. A long wall-clock wait
does not add capture-time coverage to a short replay.

## Baseline lifecycle

| State/action | Meaning |
| --- | --- |
| Learn | Accumulate bounded candidates in the observed scope |
| Approve | Explicitly trust reviewed facts and create a baseline version |
| Monitor | Compare subsequent facts/models against approved state |
| Acknowledge | Record a review without changing baseline trust |
| Approve changes | Review benign candidates and version the baseline |
| Suppress | Explicit exception with retained decision context |
| Pause/resume | Control monitoring without inventing new observations |
| Relearn/reset | Deliberate baseline maintenance, not routine alert dismissal |

Use `-behavior-baseline` for an existing baseline path, `-behavior-sensor` for
explicit sensor identity and `-behavior-prefix` for configured network CIDRs.
Default capture state is under the output directory. The baseline has a
single-writer lock; concurrent captures must not mutate one file.

## Evidence and limits

| Surface | Contract |
| --- | --- |
| Discovery | ARP/DHCP/NDP bindings, service edges, DNS and learned/configured prefixes |
| Lateral patterns | Distinct-target SMB/RDP/SSH relationships and inferred sequences |
| Traffic models | Frozen packet/byte models learned over multiple windows; approved models do not silently adapt |
| Bounds | Default 10,000 facts; visible overflow prevents approving incomplete learning |
| Persistence | Atomic checkpoints and separately durable alert history |
| Health | Scope, queue/admission/drop observations, storage/detector errors and nullable unavailable counters |

Readable SMB authentication results are distinct from TCP resets, connection
attempts or encrypted sessions. A→B→C patterns are evidence hypotheses, not proof
of lateral execution. Learned DHCP leases can explain changes, but an unknown
DHCP server cannot authorize itself.

## API and live feed

`GET /api/behavior` reads state. `POST /api/behavior/change` uses the versioned
`{action, ids, reason, version}` decision contract. `/api/behavior/health` and
`BehaviorHealth.json` expose coverage. `/api/alerts/stream` supports durable
history cursors and `Last-Event-ID`; slow readers, truncation and replacement
produce explicit gaps. It is bounded, not an unbounded lossless queue.

## Recovery and policy

Corrupt snapshots are rejected without replacement. Stop capture, preserve the
damaged file and restore a known-good approved copy to a separate writable path.
Select it explicitly; without a trusted backup, select a new path and relearn.
Do not discard the only copy of approval/history evidence.

`-behavior-policy` supports source-specific maintenance intervals in UTC
nanoseconds. Exceptions expire according to capture time. Geographic/admin
policies are configuration, not observations. [Distributed sensors](distributed-collection.md)
add delivery/ACK limits that remain separate from local alert durability.
