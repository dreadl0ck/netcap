# Device profiles

`DeviceProfile` summarizes observed traffic around a MAC address. `Host` and
`Connection` describe related address/communication observations. None is an
authenticated asset inventory simply because a hostname or manufacturer is shown.

```sh
net capture -read traffic.pcap -out inventory-audit -dpi=false
net dump -read inventory-audit/DeviceProfile.ncap.gz -fields
net dump -read inventory-audit/DeviceProfile.ncap.gz -json
net triage -read inventory-audit -json
```

## Read the layers separately

| Evidence | Interpretation |
| --- | --- |
| MAC / OUI | Observed link-layer address and vendor-table attribution |
| Device IPs | Addresses seen with the device; NAT, relays and lease changes complicate ownership |
| Contacts and counters | Captured peer/traffic summary, not a complete history of all activity |
| Applications | Classifier/decoder output available in this build |
| Hostname/account bindings | Use `Hosts.json` and its provenance/conflicts |
| Behavior baseline | Explicitly reviewed state, separate from an observed profile |

Profiles depend on input link type and observation point. Routed traffic may
show a gateway MAC for remote addresses; do not assign all of those addresses to
one physical endpoint.

## Timing and bounds

Aggregate records can finalize at shutdown. A still-running capture need not
contain every completed profile. DeviceProfile contact sampling and deduplication
are bounded: inspect `ContactObservations`, `ContactCountLowerBound` and
`ContactsTruncated` rather than equating a displayed list with exact cardinality.
The implementation retains at most 4,096 sampled contacts and 65,536 dedup keys.

Use current fields from `types/netcap.proto`; historical `IPProfile` schema
snippets do not describe the current Host/Connection model. [Identity](host-identity.md)
and [behavior](behavioral-monitoring.md) guide the next investigation step.
