---
description: Network traffic analysis, structured evidence and reproducible investigations.
---

# Netcap

![Netcap — network traffic analysis](graphics/logo.png)

Netcap turns network packets into typed audit records, then connects protocol
observations to hosts, services, files, detections and investigation evidence.
Use the `net` executable to analyze PCAP/PCAPNG files, inspect a live interface,
browse results locally or supply structured evidence to an AI agent.

These docs cover the **public Go implementation**, with executable examples
targeting [v0.15.2](https://github.com/dreadl0ck/netcap/releases/tag/v0.15.2).
GitBook's `master` variant follows the public repository; historical variants
describe older interfaces. Server-side database publication may evolve without
changing the signed client protocol.

## Start with a question

| Goal | Guide |
| --- | --- |
| Produce and inspect your first records | [First capture](quickstart.md) |
| Explore captures in a browser | [Web interface](web-interface.md) |
| Identify hosts and observed accounts | [Hosts and identity](host-identity.md) |
| Explain an alert and recover its evidence | [Related evidence](evidence.md) |
| Find unusual connections or learn a baseline | [Network detections](network-detections.md), [behavioral monitoring](behavioral-monitoring.md) |
| Automate analysis with an AI client | [MCP](mcp.md) |
| Integrate records into another tool | [CSV/JSON](filtering-and-export.md), [record format](specification.md) |

## From packets to evidence

| Stage | Result |
| --- | --- |
| Capture | Packets from a file or visible interface; optional BPF selection |
| Decode | Protocol-specific records and higher-level `Connection`, `Host`, `DeviceProfile`, `Software` and `File` observations |
| Enrich | Local IANA, OUI, GeoIP, UA, HASSH and NVD data where enabled and available |
| Investigate | Rules, network detections, approved behavioral baselines, identity bindings and related-record pivots |
| Preserve | Audit files, capture-health manifests and optional packet/stream evidence |

Local capture normally writes one compressed protobuf file per emitted record
type, such as `TCP.ncap.gz`. `dump` reads those files; `triage` reads host-identity
reports; `investigate` queries and exports bounded evidence. [Commands](commands.md)
explains the division.

## Understand what was observed

A passive capture sees only traffic reaching its input. Packet loss, truncation,
encryption and absent handshake data limit interpretation. Protocol recognition
does not imply complete application decoding; a CVE match does not prove
exploitation; a connection attempt does not establish authentication failure.
Health and completeness fields make these limits inspectable.

Netcap's Go runtime and bounded parsers reduce some implementation risks, but
native libpcap/DPI/YARA integrations are part of the build-dependent trust
boundary. See [installation](installation.md), [capture health](evidence.md) and
[service hosting](web-interface.md#hosting-boundary).

## Source and license

The public Go framework is [GPL-3.0-or-later](license.md). Dataset and native
dependency licenses remain separate. The [public repository](https://github.com/dreadl0ck/netcap)
contains source, tests, schemas and release build recipes. This documentation
does not describe commercial desktop editions or promise parity with other
implementations.
