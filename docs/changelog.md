---
description: Detailed Version History Information
---

# Changelog

## v0.16.5

The [Go release](https://github.com/dreadl0ck/netcap/releases/tag/v0.16.5)
ships the [analyst web UI changes](../RELEASE_NOTES.md#analyst-web-ui) on top of
v0.16.4. The chart endpoint answers `204 No Content` when the selected scope has
no plottable values; capture and decoder behavior is unchanged from v0.16.4.

## v0.16.4

The [Go release](https://github.com/dreadl0ck/netcap/releases/tag/v0.16.4)
ships the [capture-evidence and resource fixes](../RELEASE_NOTES.md#capture-evidence-and-resource-fixes).
The [qualification receipt](../internal/collector/testdata/recheck-v0163.json)
records the 148-capture MTA replay, 4,965 additional replay units, memory
measurements and matched Linux performance trials. Unsupported formats and
damaged inputs retain their explicit coverage dispositions.

## v0.16.3

The [Go release](https://github.com/dreadl0ck/netcap/releases/tag/v0.16.3)
ships commit `d0a9c4705e67c4efbac6c1b0ead682ffa50aa8a6`, including both recheck-fix
commits. See [release notes](../RELEASE_NOTES.md#recheck-reliability-and-portable-runtimes)
for the changes and [recheck qualification](reassembly.md#recheck-qualification)
for measured coverage and the remaining full-corpus/performance limits.

## v0.16.2

The [Go release](https://github.com/dreadl0ck/netcap/releases/tag/v0.16.2)
ships commit `2f0c3fc0a5a083dd7341803f9968b84058c2946e`.
[NETCAP Pro 1.5.1](https://github.com/dreadl0ck/netcap-pro/releases/tag/v1.5.1)
uses that backend and shared UI.

| Area | Released fix / boundary |
| --- | --- |
| TCP byte limits | Direction closure releases queued `KeepFrom` pages after scatter/gather cleanup; fixes the Brazil replay assembler panic without restoring discarded bytes |
| Early capture failures | Reproduction metadata retains admitted source SHA-256, byte count and failed-output mapping even without a capture manifest; missing producer, RunID and effective settings remain explicitly unavailable |
| Source binding | Stale manifests and replaced source aliases are rejected; malformed captures remain failed/partial |
| Desktop diagnostics | Native save dialogs use the failed capture's local-output mapping |
| Distribution | Seven CLI variants and separate Linux amd64/arm64 `netcap-firewall` archives, supplier sources, checksums and qualification receipts |

Both macOS CLI variants are Developer ID signed and notarized. Windows Npcap
runtime operation and full clean-macOS-15 BPF/YARA operation remain uncertified;
see [installation](installation.md#binary-distributions).

## Source-only corrections

This heading preserves links to changes originally documented as source-only
after v0.15.2. The additions below shipped in v0.16.1 and remain in v0.16.2;
they do not change an already downloaded v0.15.2 archive.

Use the [current installation](installation.md) and installed help for packaged
availability. Standalone firewall bundles have a separate qualification process
in `scripts/firewall_release.py`; publication does not approve a production
appliance or promote OCI images.

| Area | User-facing addition / boundary |
| --- | --- |
| Firewall | [Rootless HTTP WAF quickstart](APPLICATION_FIREWALL.md#quickstart), native/Coraza policies, routed TLS, WS/gRPC and optional HTTP/3 ingress; separate Linux network/enforcer opt-in |
| Firewall control | Scoped REST/MCP authorization, managed revisions/rollback, fleet ownership, shared native state, bounded audit/metrics and SQLite/Postgres recovery; [operator contract](APPLICATION_FIREWALL.md#policy-control-and-replica-state) |
| Incremental HTTP/1 | `-incremental-http` emits completed supported transactions while TCP remains open; observed handshake and bounded framing required; [fallback/limits](reassembly.md#incremental-transactions) |
| Capture lifecycle | `-capture-time-idle-expiry`, independent live maintenance/output snapshots, completed TCP release and separate shared reader/page/parser budgets; [resource controls](workers.md) are not global RSS limits |
| Rule correlation | [Scoped capture-time groups and typed joins](RULES_ENGINE.md#scoped-capture-time-rules), bounded lateness/reload/finalization; tuple identity alone does not establish session or causality |
| Alert delivery | [Durable private webhook outbox](RULES_ENGINE.md#durable-webhook-delivery), stable idempotency key, bounded retries and explicit receipts; at-least-once receivers must deduplicate |
| Credentials | [Every emitted Secret occurrence](credential-analysis.md), observed protocol/outcome context and safe alert/metric projections; original audit remains sensitive |
| Analyst workspace | [Explicit multi-capture catalogue](evidence.md#bound-analyst-workspace), exact occurrence resolution, saved queries/reviewed reports and coverage-qualified charts |
| Packet evidence | `split --inspect`, bounded BPF/time subsets and disjoint time shards with hashes/manifests; [selection contract](evidence.md#export-packet-evidence) |
| Reanalysis / diagnostics | [Isolated source-bound child runs](evidence.md#reanalyze-a-capture), restart recovery and [metadata-only reproduction export](evidence.md#export-reproduction-metadata) with optional reviewed safe logs |
| Native packaging | Matched YARA-X 1.22.0 C API/builders, Alpine 3.24.4 capture runtime and real YARA/BPF probes; [container build boundaries](docker-containers.md) |
| HTTP/2 visibility | [Cleartext preface/HPACK and validated h2c](protocol-support.md#cleartext-http2-evidence), multiplexed HTTP record IDs and explicit framing/loss qualifications; no generic gRPC payload claim |
| Readers / audit semantics | Legacy PCAP reader compatibility, effective-transport CommunityID, directional protocol evidence, qualified RDP outcomes and capture-time TLS assessment; [record contract](protocol-support.md#correlation-and-security-outcomes) |

These Go contracts do not establish native Rust child-analysis parity,
incremental decoding for every protocol or qualification on every deployment
platform. Missing capture fields and unobserved protocol outcomes remain unknown.

| Change | Migration/qualification |
| --- | --- |
| S7 requests gated by message role; response allowlist uses destination initiator | “Completed” rule renamed to acknowledgment; no header-only execution claim |
| DNP3 group 60 variation 1 mapped to Class 0; 2–4 to classes 1–3 | Corrected integrity-poll rule ships in v0.16.2; v0.15.2 needs an external corrected pack or upgrade |
| Grouped offline rules and audit readiness | Released `investigate rules`; separate pack format and finalized-capture requirements |
| Documentation contracts | `make docs-check` runs published lab commands; `make docs-source-check` checks schema/rule examples |

## v0.15.2

The [binary release](https://github.com/dreadl0ck/netcap/releases/tag/v0.15.2)
ships signed community database installation and qualified native runtimes.
v0.15.0/v0.15.1 were runtime-qualification candidates.

| Area | Released change |
| --- | --- |
| Updates | Embedded Ed25519 verification root, expiring signed releases, monotonic sequence/epoch and exact hashes |
| Data | NVD SQLite schema 2, DB-IP City/ASN, IANA, UA-parser and pinned BSD HASSH |
| Installation | Cross-process update lock, staged activation and preservation on failure |
| Linux | Embed the actual built WebUI through an explicit Docker build context |
| macOS | Relocated bundled native libraries; DPI macOS 26+, nodpi macOS 15+ |
| Provenance | Native-runtime hashes, package notices and corresponding source assets |
| Windows | Qualified signed download/update and structured CVE lookup |

### Migration checklist

| Previous workflow | Current workflow |
| --- | --- |
| Old executable/CLI recipes | `net --version`, [command inventory](commands.md) and installed help |
| CSV through `export` | `dump -csv`; `export` serves Prometheus metrics |
| Generic generated config | Explicit supported flags/env; `-gen-config` remains unimplemented |
| v0.14.0 community snapshot | Frozen `/dbs/v3/`; upgrade for signed refreshes |
| v1/v2 database endpoint or SQLite schema 1 | Upgrade client and download schema 2; do not edit a version field |
| Nmap/CMS/DHCP OS/JA3 catalogue assumptions | [Current source inventory](database-updates.md) and bounded built-in service signatures |
| Older `agent`/`collect` wire format | Upgrade both ends; see distributed collection below |

Publisher policy/source-provenance changes after the v0.15.2 tag are source/server
changes, not additional features of that binary. The remaining sections retain
historical release context; use the current topic guides for executable recipes.

## v0.13.0

The v0.13.0 notes recorded 524 passing tests in affected Go packages.
[Release notes](https://github.com/dreadl0ck/netcap/blob/v0.13.0/RELEASE_NOTES.md) describe
the evidence-linking and capture-time DNS features.

| Change | Evidence |
| --- | --- |
| Scoped cross-protocol linking, immutable audit references, capture-time DNS context and independent feature switches | `29464936`, [release notes](https://github.com/dreadl0ck/netcap/blob/v0.13.0/RELEASE_NOTES.md#hunting-evidence) |
| Shared UI 0.13.0, including related evidence and tagless-alert rendering | `cmd/capture/webui/frontend/packages/netcap-ui/package.json` |

## v0.10.3

### Native DPI

`go-dpi v1.5.0` adds worker-owned native contexts and incremental flow state. Inspection stops after 10 observations; consecutive duplicate enrichment calls share progress. `-dpi-workers` / `NC_DPI_WORKERS` selects the context count; `1` minimizes native context memory.

| DPI microbenchmark | replay baseline | incremental integration |
| --- | --- | --- |
| LPI + nDPI, 10 unidentified packets | 98.75 µs/flow | 17.42 µs/flow |
| LPI + nDPI, 100 unidentified packets | 1,395.57 µs/flow | 40.53 µs/flow |
| 32,768 single-packet flows, one nDPI context | 109.1 MiB peak RSS | 64.7 MiB peak RSS |

Measured on Apple M5 Max, Go 1.27.0, nDPI 4.14.0. These are DPI microbenchmarks; whole-capture throughput depends on the workload. Eight contexts used 126.2 MiB in the single-packet probe. Small unidentified first packets are replayed once when promoted to persistent native state. Samples and reproduction commands: `internal/dpi/performance-results.json` and `zeus/scripts/benchmark-c-dpi.sh`.

### Geolocation

`net util -download-dbs` bundles DB-IP Lite City geolocation. `-geoProviders` selects the providers; `docs/resolvers.md` records attribution and configuration. Installs upgraded from the bleve layout are prompted to download `netcap.sqlite`.

### Distributed collection

The `net agent` / `net collect` wire format is new and incompatible with v0.10.2 and earlier. Nothing working depended on the old one: **no earlier release produced readable output.** It sent records without length prefixes, so every `.ncap.gz` after the header was unreadable. Setup: [distributed-collection.md](distributed-collection.md).

| v0.10.2 and earlier | now |
| --- | --- |
| records sent without length prefixes | each record length-delimited, and validated before it is written |
| first batch per file dropped | written |
| unlocked shared file map, concurrent gzip writes | one locked writer per client and type |
| 10 KiB UDP receive buffer; a full batch, or any short or forged datagram, panicked the collector | TCP frames up to 4 MiB; malformed input closes that connection only |
| UDP + NaCl box, no reconnect or delivery guarantee | TLS 1.3, acknowledged batches, reconnect with backoff, in-memory resend queue |
| any client key accepted; client-chosen `ClientID` used as a directory (`../`, absolute paths) | allowlist of pinned agent keys; the directory is the allowlist name |
| stream and abstract decoders never drained, so they blocked once their channel filled; no stream reassembly | all decoders drained; `-reassemble-connections` on by default |
| partial batches never sent, nothing sent on exit | `-flush-interval`, and delivery of queued batches on SIGINT/SIGTERM |
| agent panicked on teardown (`NumStreamWorkers` 0) | agent starts from the decoder defaults |

Removed flags: `-pubkey` (agent), `-privkey`, `-membuf-size` (collector), `-config` and `-gen-config` on both (they were never implemented). `types.Batch.ClientID` is reserved.

## v0.5 - April 2020

### Fixed

* multiple bugs in the stream reassembly
* several panics during parsing in gopacket 

### Changed

* CLI interface refactored: single binary app with subcommands, stripped size ~**17MB**
* Updated units tests
* Documentation updates
* Updated Docker containers for **Ubuntu** and **Alpine**
* Compiled with **Go 1.14.2**
* removed custom audit records Link-, Network- and TransportFlow

### New Features

* **Maltego** integration
* **File** audit records
* **Diameter** protocol audit records
* **SMTP** audit records
* **POP3** support for extracting Mails
* **JA3S** support and separate audit record for **TLSServerHello**
* New configuration options: via **environment variables** or **configuration** file
* Resolvers package for **Geolocation**, **DNS** and **Service** lookups and **whitelisting**
* Deep Packet Inspection via **nDPI** and **libprotoident**
* **DeviceProfile** Audit records, to capture the behavior of a single device within a traffic dump
* Added an integration for **bash-completion** support
