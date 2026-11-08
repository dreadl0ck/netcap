---
description: Choose the public Go command for the job.
---

# Commands

Current Go source registers the commands below in `cmd/net/main.go`. Run `net -h` and
`net COMMAND -h` for their installed options. The executable is `net`; version
inspection is `net --version`, not a `version` subcommand.

| Command | Job | Guide |
| --- | --- | --- |
| `capture` | PCAP/PCAPNG, live packets and local/upload WebUI | [Packet collection](packet-collection.md) |
| `dump` | Read audit files, discover fields, filter and emit CSV/JSON | [Record inspection](filtering-and-export.md) |
| `triage` | Inspect capture-derived `Hosts.json` identities | [Hosts and identity](host-identity.md) |
| `investigate` | Flow queries, related records, evidence exports and bounded experiments | [Evidence](evidence.md), [flow analysis](flow-analysis.md) |
| `util` | Interfaces, schemas, timestamps and database operations | [Database updates](database-updates.md) |
| `mcp` | Stdio Model Context Protocol server | [AI agents](mcp.md) |
| `licenses` | Distribution license/notice information | [License](license.md) |
| `agent` | TLS-authenticated remote sensor | [Distributed collection](distributed-collection.md) |
| `collect` | Receive agent batches | [Distributed collection](distributed-collection.md) |
| `export` | Prometheus-oriented audit metrics exporter | [Metrics](metrics.md) |
| `proxy` | HTTP/HTTPS reverse proxy records | [HTTP proxy](http-proxy.md) |
| `label` | Suricata/custom mappings for dataset labels | [Labeling](audit-record-labeling.md) |
| `transform` | Maltego transform integration | [Maltego](maltego-integration.md) |
| `inject` | Linux NFQueue inline manipulation | [Response actions](FIREWALL_RESPONSE_ACTIONS.md) |
| `split` | Read-only capture inspection, bounded packet subsets and time shards | [Packet evidence](evidence.md#export-packet-evidence) |
| `firewall` | Explicit WAF, protocol gateways, policy control and scoped Linux enforcement | [Application firewall](APPLICATION_FIREWALL.md) |

`split` and `firewall` are current-source additions after v0.15.2; the v0.15.2
archive does not expose them. `analyze` remains unregistered. A source directory
or legacy completion result alone does not establish an executable interface.

The standalone `netcap-firewall` executable accepts `serve`, `validate`,
`healthcheck`, `gateway`, `network` and its other subcommands directly;
`net firewall` accepts the same subcommands with the prefix. Its `version`
subcommand is separate from the capture executable's `net --version`.

## Common operations

The [offline grouped rule evaluator](RULES_ENGINE.md#offline-grouped-thresholds)
(`investigate rules`) is available in current source after v0.15.2. It is not
present in the v0.15.2 release binary. The [sensor bundle commands](sensor-bundles.md)
are a separate completed-output workflow from live agent transport.
Current source also adds [scoped capture rules](RULES_ENGINE.md#scoped-capture-time-rules)
and the explicit `investigate deliver-alerts` [webhook outbox](RULES_ENGINE.md#durable-webhook-delivery).

```sh
net util -interfaces
net capture -overview
net capture -read example.pcap -out analysis -dpi=false -geoDB=false
net dump -read analysis/UDP.ncap.gz -fields
net dump -read analysis/UDP.ncap.gz -json
net triage -read analysis -json
net investigate related -read analysis -type Connection -ordinal 0
```

Only query a type/ordinal that exists in your capture. For advanced commands,
the [generated MCP catalogue](mcp/tools.md) is a different interface, not a CLI
alias list. The source command/flag registrations are the reference for scripting.
