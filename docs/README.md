---
description: Turn network captures into structured records you can search and investigate.
---

# Netcap

![](.gitbook/assets/logo.png)

Netcap turns network packets into typed audit records and links them to hosts, services, files, detections and evidence. Use the `net` executable to analyze PCAP/PCAPNG files, capture from a live interface, browse results in a browser or give structured evidence to an AI agent.

These docs cover the open-source Go implementation, currently [v0.16.5](https://github.com/dreadl0ck/netcap/releases/tag/v0.16.5). The `master` variant follows the current source and may describe flags your release does not have, so check `net --version` and `net capture -h`. Older variants describe older releases. [Releases and migration](changelog.md) lists what each release contains.

## Start with a question

| Goal                                                         | Guide                                                                                          |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| Produce and inspect your first records                       | [First capture](quickstart.md)                                                                 |
| Follow a file download from DNS lookup to extracted file     | [Investigate a file transfer](investigation-walkthrough.md)                                    |
| Explore captures in a browser                                | [Web interface](web-interface.md)                                                              |
| Identify hosts and observed accounts                         | [Hosts and identity](host-identity.md)                                                         |
| Explain an alert and recover its evidence                    | [Related evidence](evidence.md)                                                                |
| Find unusual connections or learn a baseline                 | [Network detections](network-detections.md), [behavioral monitoring](behavioral-monitoring.md) |
| Automate analysis with an AI client                          | [MCP](mcp.md)                                                                                  |
| Integrate records into another tool                          | [CSV/JSON](filtering-and-export.md), [record format](specification.md)                         |
| Inspect HTTP transactions before a TCP connection closes     | [Incremental transactions](reassembly.md#incremental-transactions)                             |
| Search captures, save queries and review reports             | [Bound analyst workspace](evidence.md#bound-analyst-workspace)                                 |
| Inspect or split packet evidence without changing the source | [Packet evidence](evidence.md#export-packet-evidence)                                          |
| Deliver redacted alerts with retries                         | [Webhook delivery](RULES_ENGINE.md#durable-webhook-delivery)                                   |
| Filter traffic before it reaches an application              | [Application firewall quickstart](APPLICATION_FIREWALL.md#quickstart)                          |

## From packets to evidence

| Stage       | Result                                                                                                          |
| ----------- | --------------------------------------------------------------------------------------------------------------- |
| Capture     | Packets from a file or a visible interface, optionally filtered with BPF                                        |
| Decode      | Protocol-specific records and higher-level `Connection`, `Host`, `DeviceProfile`, `Software` and `File` records |
| Enrich      | Local IANA, OUI, GeoIP, UA, HASSH and NVD data, where enabled and available                                     |
| Investigate | Rules, network detections, approved behavioral baselines, identity bindings and related-record pivots           |
| Preserve    | Audit files, capture-health manifests and optional packet and stream evidence                                   |

A capture normally writes one compressed protobuf file per record type, such as `TCP.ncap.gz`. `dump` reads those files, `triage` reads host-identity reports and `investigate` queries and exports evidence. [Commands](commands.md) describes each command.

## What a capture can show

Netcap only sees traffic that reaches its input. Packet loss, truncation and encryption limit what it can decode, and the health and completeness fields show where that happened. A CVE match does not mean a host was exploited, and a failed connection is not necessarily a failed login.

libpcap, DPI and YARA are native libraries that depend on how you built or installed Netcap. See [installation](installation.md), [capture health](evidence.md) and [service hosting](web-interface.md#hosting-boundary).

## Source and license

The Go framework is [GPL-3.0-or-later](license.md). Datasets and native dependencies have their own licenses. The [public repository](https://github.com/dreadl0ck/netcap) contains the source, tests, schemas and release build recipes.
