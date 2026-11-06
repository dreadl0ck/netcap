# Network detections

Go's network-detection engine observes packet and application patterns separately
from YAML rules and approved behavioral baselines. `-network-detection` is
enabled by default; `-network-detection-config` supplies its JSON policy.

| Mechanism | Input | Interpretation |
| --- | --- | --- |
| YAML rules | Typed audit records | Explicit expression/threshold/sequence match |
| Network detections | Packet/application observations | Pattern, indicator or policy evidence |
| Behavior | Scoped facts and explicitly approved baseline | Change/deviation from reviewed state |

Use the alert's detector identifier, evidence and observation time to decide
which mechanism produced it. A benign policy observation is not necessarily an
attack; a scan/beacon pattern alone does not prove compromise.

## Investigate a finding

1. Check capture scope, gaps and admission health.
2. Read detector evidence rather than inferring intent from the title.
3. Compare endpoints and time with decoded transactions and connection summaries.
4. Preserve protocol visibility: encrypted traffic can expose timing/edges
   without exposing authentication or application commands.
5. Add benign controls before changing a threshold or allowlist.

The engine includes scan, DNS, periodic-connection and transfer patterns, plus
application-policy observations. Some application findings finalize after record
processing; absence before completion is not a negative verdict.

## Indicators and policy

The versioned JSON types in
[`internal/networkdetect/config.go`](https://github.com/dreadl0ck/netcap/blob/v0.15.2/internal/networkdetect/config.go)
define thresholds, approved sources and IP/domain indicators. Indicators require
source, version and capture-time validity. There is no bundled live intelligence
feed or implicit STIX/TAXII ingestion. Distinguish an indicator match from
independently verified malicious activity.

The WebUI's Alerts view displays available evidence. [Related-record linking](evidence.md)
does not automatically treat these alerts as YAML-rule matched records.
[Behavioral monitoring](behavioral-monitoring.md) has a separate learning and
approval lifecycle.
