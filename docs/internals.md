# Architecture

The public Go executable is a concurrent packet-to-record pipeline with optional
enrichment, detectors and evidence retention. Its internal packages are not a
stable public Go SDK merely because their source is available.

| Stage | Code | Responsibility |
| --- | --- | --- |
| CLI | `cmd/net`, `cmd/capture` | Registered commands, options and lifecycle |
| Collection | `internal/collector` | Read input, account for admission, dispatch work and finalize |
| Packet decoding | `internal/decoder/packet` | Typed layer/protocol records |
| Stream assembly | `internal/reassembly`, `internal/decoder/stream` | Directional TCP/UDP conversations and application parsers |
| Enrichment | `internal/resolvers`, `internal/vulndb` | Local source lookup and structured applicability |
| Detectors | `internal/rules`, `internal/networkdetect`, `internal/behavior` | Expressions, pattern evidence and approved baseline changes |
| Persistence | `internal/netio`, `types` | Record framing, output writers and schemas |
| Investigation | `internal/evidence`, `internal/evidencelink`, `internal/identity` | Source/scope witnesses, links and host/account provenance |
| Interfaces | `cmd/capture/webui`, `internal/mcp` | Embedded browser/API and MCP tools |

## Ownership and timing

Packet admission, worker execution, stream completion and postprocessing are
different lifecycle phases. Stream/aggregate records can be emitted after later
packets have already produced packet records. `dump` sorting does not alter this
execution history. Capture-time correlation and browse-time evidence linking
therefore have different guarantees.

Flow-aware dispatch keeps related traffic together where its key is available.
Native DPI contexts and pending queues are separately bounded. Backpressure and
capture loss are observations to inspect, not conditions a generic concurrency
diagram can rule out. [Workers](workers.md) lists practical budgets.

## Data contracts

| Contract | Reference |
| --- | --- |
| Audit wire format | [Specification](specification.md), `types/netcap.proto` |
| NVD SQLite | `internal/vulndb/SCHEMA.md`, schema 2 |
| Source/signature verification | [Database updates](database-updates.md) |
| Capture/stream scope | [Evidence](evidence.md) |
| Typed rule expressions | [Rules engine](RULES_ENGINE.md) |

Build tags change native integrations and available paths. Separate the public
Go release contract from source-only experimental code and from another
implementation's API. [Adding decoders](extension.md) covers extension points.
