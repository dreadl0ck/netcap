# Netcap v0.13.0 and netcap-ui 0.13.0

Release features and scoped verification are listed below.

Release boundary: `v0.12.0..29464936` plus prepared 0.13.0 metadata and performance
documentation. The shared UI follows that source boundary; Rust-only changes are
not included in the Go or UI feature list.

## Hunting evidence

| Feature | Interface / behavior |
| --- | --- |
| Related evidence | `/api/evidence/related`, `net investigate related`, Connections rows and alert details link DNS, connections, protocol records and alerts |
| Verifiable references | References bind to audit-file content hashes; capture interface/VLAN scope and bounded time windows reject ambiguous joins |
| Capture-time DNS context | `--dns-resolution-context` snapshots matched UDP DNS answers onto Connection observations for rules; names and timestamp overflow are checked |
| Bounded, scoped joins | Per-directory index and result limits report truncation; temporal, interface and VLAN scope checks withhold ambiguous relationships instead of guessing |
| Feature controls | Settings → Features switches evidence linking and network detections independently |
| Alert rendering | Rule alerts without tags render without crashing the Alerts page |

`@dreadl0ck/netcap-ui` 0.13.0 contains the related-evidence views and feature
controls in `cmd/capture/webui/frontend/packages/netcap-ui`. Package publication
targets GitHub Packages (`https://npm.pkg.github.com`).

## Go and Rust performance review

Completed screening: 61 benchmark steps and three alternating measured repeats;
Go `29464936`, Rust `58170da`, Apple M5 Max, Go 1.27.0/Rust 1.90.0.

| Workload, 1 worker | Go s | Rust s | Go / Rust RSS MiB | Selected wire parity |
| --- | ---: | ---: | ---: | --- |
| UDP 8 MiB, audit-only | 0.114 | 0.029 | 75.5 / 29.3 | yes |
| DNS 8 MiB, audit-only | 0.459 | 0.156 | 184.9 / 28.3 | yes |
| Snort common packets | 1.123 | 1.176 | 259.8 / 80.0 | yes, 981,061 records |
| Snort all audits | 19.310 | 1.347 | 2259.6 / 96.9 | no |
| DNS 1 MiB, evidence on | 0.158 | 0.450 | 94.4 / 29.6 | audits only |

These are screening medians, not universal speedups. Snort all-audit output differs
(1,066,685 Go / 1,056,604 Rust records); evidence durability is outside audit parity.
Targeted checks passed 1,000 hunting-field, 848 DNS-context and 6,656 evidence-link
comparisons. Go's affected packages passed 524 tests.
[Completed provenance](https://github.com/dreadl0ck/netcap-rs/blob/main/perf/results/small-review-20261009.json).

### Earlier exploratory measurements

Provisional Apple M5 Max/macOS arm64 observations compare Go `29464936` with
Rust `58170da`, using five alternating measured repeats, warm caches, varied
addresses and plain selected protobuf audits. Another benchmark ran concurrently;
these are review measurements, not release-qualified speedup claims.
Those runs also inherited network-detection defaults; the prepared rerun disables
detection and behavior explicitly, so effective-feature parity must be rechecked.

| 64 MiB workload, 1 worker | Evidence sidecars | Go s | Rust s | Go / Rust RSS MiB |
| --- | --- | ---: | ---: | ---: |
| UDP | off | 0.227 | 0.067 | 142.2 / 28.8 |
| DNS | off | 2.749 | 0.994 | 207.0 / 27.7 |
| UDP | on | 0.293 | 2.067 | 145.0 / 29.3 |
| DNS | on | 2.980 | 29.267 | 208.3 / 29.2 |

Selected audit records match by full protobuf multiset. Evidence settings reverse
the observed ranking; sidecar equivalence and durability are separate contracts.
Real-capture comparison remains pending after a header-only gzip Alert file tripped
the old validator. The improvement plan prioritizes evidence-checkpoint profiling
and batching, ingress decode reuse, and Go allocation/GC pressure.

Provenance and reproduction:
[Rust performance review](https://github.com/dreadl0ck/netcap-rs/blob/main/perf/README.md#current-comparison-and-improvement-plan),
[compact snapshot](https://github.com/dreadl0ck/netcap-rs/blob/main/perf/results/latest-review-20261009.json),
and [Go performance log](docs/PERFORMANCE_ANALYSIS.md#go-and-rust-comparison).
The existing October 5 comparison used Go v0.9.15 and does not describe v0.13.0.
