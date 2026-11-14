---
description: Which net command to use for which job.
---

# Commands

The executable is `net`. Run `net -h` and `net COMMAND -h` to see the options of your installed version. Print the version with `net --version`.

| Command       | Job                                                                | Guide                                                      |
| ------------- | ------------------------------------------------------------------ | ---------------------------------------------------------- |
| `capture`     | Read PCAP/PCAPNG files or live packets, run the local/upload WebUI | [Packet collection](packet-collection.md)                  |
| `dump`        | Read audit files, list fields, filter, write CSV/JSON              | [Record inspection](filtering-and-export.md)               |
| `triage`      | Inspect host identities in `Hosts.json`                            | [Hosts and identity](host-identity.md)                     |
| `investigate` | Flow queries, related records, evidence exports, experiments       | [Evidence](evidence.md), [flow analysis](flow-analysis.md) |
| `util`        | Interfaces, schemas, timestamps, database operations               | [Database updates](database-updates.md)                    |
| `mcp`         | Model Context Protocol server over stdio                           | [AI agents](mcp.md)                                        |
| `licenses`    | License and notice information                                     | [License](license.md)                                      |
| `agent`       | Remote sensor with TLS authentication                              | [Distributed collection](distributed-collection.md)        |
| `collect`     | Receive batches from agents                                        | [Distributed collection](distributed-collection.md)        |
| `export`      | Prometheus metrics exporter for audit records                      | [Metrics](metrics.md)                                      |
| `proxy`       | HTTP/HTTPS reverse proxy that records traffic                      | [HTTP proxy](http-proxy.md)                                |
| `label`       | Label datasets from Suricata or custom mappings                    | [Labeling](audit-record-labeling.md)                       |
| `transform`   | Maltego transforms                                                 | [Maltego](maltego-integration.md)                          |
| `inject`      | Inline packet manipulation with NFQueue (Linux)                    | [Response actions](FIREWALL_RESPONSE_ACTIONS.md)           |
| `split`       | Inspect a capture read-only, extract packet subsets, split by time | [Packet evidence](evidence.md#export-packet-evidence)      |
| `firewall`    | WAF, protocol gateways, policy control, Linux enforcement          | [Application firewall](APPLICATION_FIREWALL.md)            |

The standalone `netcap-firewall` executable takes `serve`, `validate`, `healthcheck`, `gateway`, `network` and its other subcommands directly. `net firewall` takes the same subcommands. The firewall has its own `version` subcommand, separate from `net --version`. See [Installation](installation.md#binary-distributions) for the standalone archives.

## Common operations

```sh
net util -interfaces
net capture -overview
net capture -read office-lan.pcap -out analysis -dpi=false -geoDB=false
net dump -read analysis/UDP.ncap.gz -fields
net dump -read analysis/UDP.ncap.gz -json
net triage -read analysis -json
net investigate related -read analysis -type Connection -ordinal 0
```

Only query a type and ordinal that exist in your capture.

More workflows:

* `investigate rules` evaluates [grouped threshold rules](RULES_ENGINE.md#offline-grouped-thresholds) on a finished capture.
* [Capture rules](RULES_ENGINE.md#scoped-capture-time-rules) can apply to part of a capture.
* `investigate deliver-alerts` sends alerts to a [webhook](RULES_ENGINE.md#durable-webhook-delivery) and retries failed deliveries.
* [Sensor bundle commands](sensor-bundles.md) work on completed output, not on live agent traffic.

The [MCP tool catalogue](mcp/tools.md) lists MCP tools, not CLI commands. For scripting, use `net COMMAND -h`.
