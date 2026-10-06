# Behavioral engine review

`Engine.Observe` consumes passive facts using capture timestamps. Monitoring
compares against an explicitly approved snapshot; candidates never become trusted
without `ChangeAtVersion` approval. The capture caller owns engine/sink shutdown.

| Review area | Source and invariant |
| --- | --- |
| Identity and discovery | `types.go`, `packet.go`: sensor/interface/ordered VLAN scope; normalized IPv4/IPv6; prefixes require provenance, never an assumed mask |
| Lifecycle and durability | `engine.go`, `persistence.go`, `template.go`: schema migrations, exclusive baseline ownership, atomic snapshots and immutable alert evidence |
| Correlation | `activity.go`, `rate.go`, `geography.go`: bounded windows, retransmission dedup, sampled rates, capture-time administrative exemptions; encrypted attempts do not prove failed authentication |
| Presentation | `asset.go`, `topology.go`, `health.go`: scoped joins, bounded responses, measured zero distinct from unavailable counters |
| Later evidence | `record_context.go`: retained Connection/SMB tuple/time candidates, canonical record hash and index; legacy audit records lack scope, so no exact VLAN attribution is claimed |
| Reference tests | `testdata/qualification/`: 5 cases, 38 exact positive alert records and benign PCAPs; collector tests exercise the production packet path at 1/2/4/8 workers |

Early observations do not wait for flow closure. Later-record drill-down leaves
the original alert unchanged and reports capture-time lag separately from unknown
audit emission latency. Resource caps and overflow/error counters are part of the
contract; review failure paths as well as positive fixtures.
