# Behavioral monitoring

Behavior tracks device facts, service edges and traffic models for each sensor, interface and VLAN. It is opt-in. Learning does not approve anything: new observations become part of the trusted baseline only after you approve them.

```sh
net capture -read traffic.pcap -out behavior-audit -behavior \
  -http 127.0.0.1:8080 -dpi=false
```

Open the Behavior view. A short pcap may not meet the default learning requirements of seven days of capture-time coverage and 100 observations. Waiting longer in real time does not add capture-time coverage to a short replay.

## Baseline lifecycle

| State/action    | Meaning                                                                |
| --------------- | ---------------------------------------------------------------------- |
| Learn           | Collect candidate facts in the observed scope                          |
| Approve         | Trust the facts you reviewed and create a baseline version             |
| Monitor         | Compare later facts and models against the approved state              |
| Acknowledge     | Record a review without changing baseline trust                        |
| Approve changes | Review benign candidates and create a new baseline version             |
| Suppress        | Add an exception and keep the decision context                         |
| Pause/resume    | Stop or restart monitoring without creating observations               |
| Relearn/reset   | Maintenance that rebuilds the baseline. Don't use it to dismiss alerts |

Use `-behavior-baseline` to point at an existing baseline file, `-behavior-sensor` to name the sensor and `-behavior-prefix` to give your network CIDRs. By default the state is stored in the output directory. The baseline file has a single-writer lock, so don't run concurrent captures against one file.

## Baseline walkthrough: a changed gateway MAC

This walkthrough learns the devices on a LAN, then replays a later capture in which a different device claims the gateway's IP address. You need three captures of the same network: `lan-baseline.pcap` from a quiet period, `lan-unchanged.pcap` with nothing different, and `lan-later.pcap` taken while a second machine on your lab network answers ARP for the gateway (192.168.1.1).

The learning values below are low (1 second and 4 samples) so that a short capture can finish learning. Use the defaults for a real baseline.

In terminal 1:

```sh
net capture -read lan-baseline.pcap -out baseline-audit \
  -behavior -behavior-sensor lab -behavior-prefix 192.168.1.0/24 \
  -behavior-learning 1s -behavior-min-samples 4 -dpi=false -geoDB=false \
  -http 127.0.0.1:8080
```

When the capture has finished, switch to terminal 2. Read the learning state, then approve the facts using the version it reports:

```sh
curl -fsS http://127.0.0.1:8080/api/behavior > learning.json
jq '{action: "approve", ids: [], reason: "Reviewed baseline of the lab LAN", version: .version}' learning.json > approve.json
curl -fsS -H 'Content-Type: application/json' \
  --data-binary @approve.json \
  http://127.0.0.1:8080/api/behavior/change > approved.json
jq '{mode, approved, baselineId, version}' approved.json
```

The last command should show `"mode": "monitoring"`.

Stop terminal 1 with Ctrl-C before you open the same baseline in another capture. Then replay the unchanged and the changed capture into fresh output directories, with the same sensor and prefix:

```sh
net capture -read lan-unchanged.pcap -out unchanged-audit \
  -behavior-baseline baseline-audit/Behavior.json \
  -behavior-sensor lab -behavior-prefix 192.168.1.0/24 -dpi=false -geoDB=false
net capture -read lan-later.pcap -out changed-audit \
  -behavior-baseline baseline-audit/Behavior.json \
  -behavior-sensor lab -behavior-prefix 192.168.1.0/24 -dpi=false -geoDB=false
net dump -read changed-audit/Alert.ncap.gz -json > behavior-alerts.ndjson
```

The unchanged replay should produce no baseline-deviation alerts. In the later capture, the gateway IP is claimed by a different MAC, so it should produce a baseline change observation. Look at the fact and its evidence, then confirm that the original `baselineId` and approved map are unchanged.

A new `-out` without `-behavior-baseline` starts separate learning. The saved baseline keeps its original learning criteria after a restart.

## Evidence and limits

| Area             | Details                                                                                             |
| ---------------- | --------------------------------------------------------------------------------------------------- |
| Discovery        | ARP/DHCP/NDP bindings, service edges, DNS and learned or configured prefixes                        |
| Lateral patterns | SMB, RDP and SSH connections to several distinct targets, and inferred sequences                    |
| Traffic models   | Packet and byte models learned over several windows. Once approved they stay frozen                 |
| Limits           | Default 10,000 facts. On overflow you can't approve the incomplete learning                         |
| Persistence      | Atomic checkpoints and a separate, durable alert history                                            |
| Health           | Scope, queue, admission and drop counts, storage and detector errors. Unavailable counters are null |

SMB authentication results are reported only when they are readable. TCP resets, connection attempts and encrypted sessions carry no result. A-to-B-to-C patterns are inferred from distinct-target relationships. A DHCP lease learned from a known server can explain a change, but an unknown DHCP server can't authorize itself.

## API and live feed

`GET /api/behavior` reads the state. `POST /api/behavior/change` takes a `{action, ids, reason, version}` decision. `/api/behavior/health` and `BehaviorHealth.json` report coverage.

`/api/alerts/stream` supports durable history cursors and `Last-Event-ID`. The feed is bounded: a slow reader, truncation or replacement shows up as a gap.

## Recovery and policy

A corrupt snapshot is rejected and not replaced. Stop the capture, keep the damaged file and restore a known-good approved copy to a separate writable path. Select it explicitly. If you have no trusted backup, pick a new path and relearn. Don't discard the only copy of approval or history evidence.

`-behavior-policy` sets maintenance intervals per source in UTC nanoseconds. Exceptions expire by capture time. Geographic and admin policies are configuration, not observations. [Distributed sensors](distributed-collection.md) add delivery and ACK limits that are separate from local alert durability.
