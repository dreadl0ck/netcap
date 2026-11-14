---
description: Detailed Version History Information
---

# Releases and migration

## v0.16.6

The [Go release](https://github.com/dreadl0ck/netcap/releases/tag/v0.16.6) contains the [recheck fixes](../RELEASE_NOTES.md#recheck-fixes). Stricter `policy.http-on-443`, NBNS node-status decoding, four more link types (50, 108, 117, 119), `directoryMatches` in `Hosts.json` and a non-interactive overwrite error are the visible changes. Memory use on very large captures is not addressed.

## v0.16.5

The [Go release](https://github.com/dreadl0ck/netcap/releases/tag/v0.16.5) adds the [analyst web UI changes](../RELEASE_NOTES.md#analyst-web-ui). The chart endpoint returns `204 No Content` when the selected scope has no plottable values. Capture and decoder behavior is the same as in v0.16.4.

## v0.16.4

The [Go release](https://github.com/dreadl0ck/netcap/releases/tag/v0.16.4) contains the [capture-evidence and resource fixes](../RELEASE_NOTES.md#capture-evidence-and-resource-fixes). The [qualification receipt](../internal/collector/testdata/recheck-v0163.json) records the 148-capture MTA replay, 4,965 additional replay units, memory measurements and matched Linux performance trials. Unsupported formats and damaged inputs keep their coverage status.

## v0.16.3

The [Go release](https://github.com/dreadl0ck/netcap/releases/tag/v0.16.3) is commit `d0a9c4705e67c4efbac6c1b0ead682ffa50aa8a6` and includes both recheck-fix commits. See the [release notes](../RELEASE_NOTES.md#recheck-reliability-and-portable-runtimes) for the changes, and [validation against public captures](reassembly.md#validation-against-public-captures) for the measured coverage and the remaining full-corpus and performance limits.

## v0.16.2

The [Go release](https://github.com/dreadl0ck/netcap/releases/tag/v0.16.2) is commit `2f0c3fc0a5a083dd7341803f9968b84058c2946e`. [NETCAP Pro 1.5.1](https://github.com/dreadl0ck/netcap-pro/releases/tag/v1.5.1) uses this backend and the shared UI.

| Area                   | Change                                                                                                                                                                                           |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| TCP byte limits        | When a direction closes, queued `KeepFrom` pages are released after scatter/gather cleanup. Fixes the Brazil replay assembler panic. Discarded bytes are not restored                            |
| Early capture failures | Reproduction metadata keeps the source SHA-256, byte count and failed-output mapping even without a capture manifest. Missing producer, RunID and effective settings are reported as unavailable |
| Source binding         | Stale manifests and replaced source aliases are rejected; malformed captures are reported as failed or partial                                                                                   |
| Desktop diagnostics    | Native save dialogs use the failed capture's local-output mapping                                                                                                                                |
| Distribution           | Seven CLI variants and separate Linux amd64/arm64 `netcap-firewall` archives, supplier sources, checksums and qualification receipts                                                             |

Both macOS CLI variants are Developer ID signed and notarized. Windows Npcap runtime operation and full clean-macOS-15 BPF/YARA operation are not yet certified; see [installation](installation.md#binary-distributions).

## Source-only corrections

This heading keeps older links working. The changes below shipped in v0.16.1 and are part of v0.16.2 and later.

See the [installation](installation.md) page and the installed help for what each package includes. Standalone firewall bundles are qualified separately by `scripts/firewall_release.py`.

| Area                      | Addition                                                                                                                                                                                                                           |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Firewall                  | [Rootless HTTP WAF quickstart](APPLICATION_FIREWALL.md#quickstart), native/Coraza policies, routed TLS, WS/gRPC and optional HTTP/3 ingress; separate Linux network/enforcer opt-in                                                |
| Firewall control          | Scoped REST/MCP authorization, managed revisions/rollback, fleet ownership, shared native state, audit/metrics limits and SQLite/Postgres recovery; [operator contract](APPLICATION_FIREWALL.md#policy-control-and-replica-state)  |
| Incremental HTTP/1        | `-incremental-http` emits completed supported transactions while TCP is still open. It needs an observed handshake and limited framing; [fallback and limits](reassembly.md#incremental-transactions)                              |
| Capture lifecycle         | `-capture-time-idle-expiry`, independent live maintenance/output snapshots, release of completed TCP state and separate reader/page/parser budgets; the [resource controls](workers.md) are not global RSS limits                  |
| Rule correlation          | [Scoped capture-time groups and typed joins](RULES_ENGINE.md#scoped-capture-time-rules), with limits on lateness, reload and finalization; matching tuples do not by themselves prove a session or causality                       |
| Alert delivery            | [Durable private webhook outbox](RULES_ENGINE.md#durable-webhook-delivery) with a stable idempotency key, limited retries and delivery receipts; delivery is at-least-once, so receivers must deduplicate                          |
| Credentials               | [Every emitted Secret occurrence](credential-analysis.md), with observed protocol/outcome context and safe alert/metric projections; the original audit stays sensitive                                                            |
| Analyst workspace         | [Multi-capture catalogue](evidence.md#bound-analyst-workspace), exact occurrence resolution, saved queries/reviewed reports and coverage-qualified charts                                                                          |
| Packet evidence           | `split --inspect`, BPF/time subsets and disjoint time shards with hashes and manifests; [selection contract](evidence.md#export-packet-evidence)                                                                                   |
| Reanalysis / diagnostics  | [Isolated source-bound child runs](evidence.md#reanalyze-a-capture), restart recovery and [metadata-only reproduction export](evidence.md#export-reproduction-metadata) with optional reviewed safe logs                           |
| Native packaging          | Matched YARA-X 1.22.0 C API/builders, Alpine 3.24.4 capture runtime and real YARA/BPF probes; [container build limits](docker-containers.md)                                                                                       |
| HTTP/2 visibility         | [Cleartext preface/HPACK and validated h2c](protocol-support.md#cleartext-http2-evidence), multiplexed HTTP record IDs and framing/loss qualifications. No generic gRPC payload decoding                                           |
| Readers / audit semantics | Legacy PCAP reader compatibility, effective-transport CommunityID, directional protocol evidence, qualified RDP outcomes and capture-time TLS assessment; [record contract](protocol-support.md#correlation-and-security-outcomes) |

Incremental decoding applies to HTTP/1 only. Missing capture fields and unobserved protocol outcomes are reported as unknown.

| Change                                                                           | Migration                                                                                           |
| -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| S7 requests gated by message role; response allowlist uses destination initiator | The "Completed" rule is renamed to acknowledgment; it no longer claims execution from the header    |
| DNP3 group 60 variation 1 mapped to Class 0; 2–4 to classes 1–3                  | The corrected integrity-poll rule ships in v0.16.2; on v0.15.2 upgrade or use an external rule pack |
| Grouped offline rules and audit readiness                                        | `investigate rules` is released; it uses its own pack format and needs a finalized capture          |

## v0.15.2

The [binary release](https://github.com/dreadl0ck/netcap/releases/tag/v0.15.2) adds signed community database installation and qualified native runtimes. v0.15.0 and v0.15.1 were candidates for runtime qualification.

| Area         | Change                                                                                                  |
| ------------ | ------------------------------------------------------------------------------------------------------- |
| Updates      | Embedded Ed25519 verification root, expiring signed releases, monotonic sequence/epoch and exact hashes |
| Data         | NVD SQLite schema 2, DB-IP City/ASN, IANA, UA-parser and pinned BSD HASSH                               |
| Installation | Cross-process update lock, staged activation and preservation on failure                                |
| Linux        | The built WebUI is embedded through the Docker build context                                            |
| macOS        | Relocated bundled native libraries; DPI macOS 26+, nodpi macOS 15+                                      |
| Provenance   | Native-runtime hashes, package notices and corresponding source assets                                  |
| Windows      | Qualified signed download/update and structured CVE lookup                                              |

### Migration checklist

| Previous workflow                          | Current workflow                                                                    |
| ------------------------------------------ | ----------------------------------------------------------------------------------- |
| Old executable/CLI recipes                 | `net --version`, [command inventory](commands.md) and installed help                |
| CSV through `export`                       | `dump -csv`; `export` serves Prometheus metrics                                     |
| Generic generated config                   | Use the supported flags and environment variables; `-gen-config` is not implemented |
| v0.14.0 community snapshot                 | Frozen `/dbs/v3/`; upgrade for signed refreshes                                     |
| v1/v2 database endpoint or SQLite schema 1 | Upgrade the client and download schema 2; do not edit a version field               |
| Nmap/CMS/DHCP OS/JA3 catalogue assumptions | [Current source inventory](database-updates.md) and built-in service signatures     |
| Older `agent`/`collect` wire format        | Upgrade both ends; see distributed collection below                                 |

The sections below cover older releases. For current commands, use the topic guides.

## v0.13.0

The v0.13.0 notes recorded 524 passing tests in affected Go packages. The [release notes](https://github.com/dreadl0ck/netcap/blob/v0.13.0/RELEASE_NOTES.md) describe the evidence-linking and capture-time DNS features.

| Change                                                                                                               | Evidence                                                                                                        |
| -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Scoped cross-protocol linking, immutable audit references, capture-time DNS context and independent feature switches | `29464936`, [release notes](https://github.com/dreadl0ck/netcap/blob/v0.13.0/RELEASE_NOTES.md#hunting-evidence) |
| Shared UI 0.13.0, including related evidence and tagless-alert rendering                                             | `cmd/capture/webui/frontend/packages/netcap-ui/package.json`                                                    |

## v0.10.3

### Native DPI

`go-dpi v1.5.0` adds worker-owned native contexts and incremental flow state. Inspection stops after 10 observations, and consecutive duplicate enrichment calls share progress. `-dpi-workers` / `NC_DPI_WORKERS` sets the number of contexts; `1` uses the least native memory.

| DPI microbenchmark                           | replay baseline    | incremental integration |
| -------------------------------------------- | ------------------ | ----------------------- |
| LPI + nDPI, 10 unidentified packets          | 98.75 µs/flow      | 17.42 µs/flow           |
| LPI + nDPI, 100 unidentified packets         | 1,395.57 µs/flow   | 40.53 µs/flow           |
| 32,768 single-packet flows, one nDPI context | 109.1 MiB peak RSS | 64.7 MiB peak RSS       |

Measured on Apple M5 Max, Go 1.27.0, nDPI 4.14.0. These are DPI microbenchmarks; whole-capture throughput depends on the workload. Eight contexts used 126.2 MiB in the single-packet test. Small unidentified first packets are replayed once when they are promoted to persistent native state. Samples and commands to reproduce them: `internal/dpi/performance-results.json` and `zeus/scripts/benchmark-c-dpi.sh`.

### Geolocation

`net util -download-dbs` bundles DB-IP Lite City geolocation. `-geoProviders` selects the providers; `docs/resolvers.md` records attribution and configuration. Installs upgraded from the bleve layout are prompted to download `netcap.sqlite`.

### Distributed collection

The `net agent` / `net collect` wire format is new and incompatible with v0.10.2 and earlier. No earlier release produced readable output: it sent records without length prefixes, so every `.ncap.gz` was unreadable after the header. Setup: [Distributed collection](distributed-collection.md).

| v0.10.2 and earlier                                                                                         | now                                                                           |
| ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| records sent without length prefixes                                                                        | each record length-delimited, and validated before it is written              |
| first batch per file dropped                                                                                | written                                                                       |
| unlocked shared file map, concurrent gzip writes                                                            | one locked writer per client and type                                         |
| 10 KiB UDP receive buffer; a full batch, or any short or forged datagram, panicked the collector            | TCP frames up to 4 MiB; malformed input closes that connection only           |
| UDP + NaCl box, no reconnect or delivery guarantee                                                          | TLS 1.3, acknowledged batches, reconnect with backoff, in-memory resend queue |
| any client key accepted; client-chosen `ClientID` used as a directory (`../`, absolute paths)               | allowlist of pinned agent keys; the directory is the allowlist name           |
| stream and abstract decoders never drained, so they blocked once their channel filled; no stream reassembly | all decoders drained; `-reassemble-connections` on by default                 |
| partial batches never sent, nothing sent on exit                                                            | `-flush-interval`, and delivery of queued batches on SIGINT/SIGTERM           |
| agent panicked on teardown (`NumStreamWorkers` 0)                                                           | agent starts from the decoder defaults                                        |

Removed flags: `-pubkey` (agent), `-privkey`, `-membuf-size` (collector), `-config` and `-gen-config` on both (they were never implemented). `types.Batch.ClientID` is reserved.

## v0.5 - April 2020

### Fixed

* multiple bugs in the stream reassembly
* several panics during parsing in gopacket

### Changed

* CLI interface refactored: single binary app with subcommands, stripped size \~**17MB**
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
