---
description: Detailed Version History Information
---

# Changelog

## v0.13.0

Affected Go packages pass 524 tests. [Release notes](../RELEASE_NOTES.md) describe
the evidence-linking and capture-time DNS features.

| Change | Evidence |
| --- | --- |
| Scoped cross-protocol linking, immutable audit references, capture-time DNS context and independent feature switches | `29464936`, [release notes](../RELEASE_NOTES.md#hunting-evidence) |
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
