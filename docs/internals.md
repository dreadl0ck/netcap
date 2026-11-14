# Architecture

Netcap is a concurrent pipeline that turns packets into records, with optional enrichment, detectors and evidence retention. The internal Go packages are not a public SDK.

| Stage           | Code                                                              | Responsibility                                                |
| --------------- | ----------------------------------------------------------------- | ------------------------------------------------------------- |
| CLI             | `cmd/net`, `cmd/capture`                                          | Registered commands, options and lifecycle                    |
| Collection      | `internal/collector`                                              | Read input, account for admission, dispatch work and finalize |
| Packet decoding | `internal/decoder/packet`                                         | Typed layer/protocol records                                  |
| Stream assembly | `internal/reassembly`, `internal/decoder/stream`                  | Directional TCP/UDP conversations and application parsers     |
| Enrichment      | `internal/resolvers`, `internal/vulndb`                           | Local source lookup and structured applicability              |
| Detectors       | `internal/rules`, `internal/networkdetect`, `internal/behavior`   | Expressions, pattern evidence and approved baseline changes   |
| Persistence     | `internal/netio`, `types`                                         | Record framing, output writers and schemas                    |
| Investigation   | `internal/evidence`, `internal/evidencelink`, `internal/identity` | Source/scope witnesses, links and host/account provenance     |
| Interfaces      | `cmd/capture/webui`, `internal/mcp`                               | Embedded browser/API and MCP tools                            |

## Ownership and timing

Packet admission, worker execution, stream completion and postprocessing are separate phases. Stream and aggregate records can be written after later packets have already produced packet records, so the order of records in a file is not the order of packets. `dump` sorting does not change when a record was written. For the same reason, capture-time correlation and browse-time evidence linking give different guarantees.

Packets of the same flow go to the same worker when a flow key is available. DPI contexts and pending queues have their own limits. [Workers](workers.md) lists the budgets. Check queue and capture-loss counters on real runs.

## Data contracts

| Contract                      | Reference                                               |
| ----------------------------- | ------------------------------------------------------- |
| Audit wire format             | [Specification](specification.md), `types/netcap.proto` |
| NVD SQLite                    | `internal/vulndb/SCHEMA.md`, schema 2                   |
| Source/signature verification | [Database updates](database-updates.md)                 |
| Capture/stream scope          | [Evidence](evidence.md)                                 |
| Typed rule expressions        | [Rules engine](RULES_ENGINE.md)                         |

Build tags change which native integrations are compiled in. [Adding decoders](extension.md) covers the extension points.

## Decoder qualification

These files decide which decoder claims a conversation and check that decoders emit correct records.

| Reference                                                          | What it checks                                                             |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| `internal/decoder/stream/selection.go`                             | Evidence-specificity ranking and transport/port eligibility                |
| `decoder_matching_test.go`, `confusable_test.go` in that directory | Competing decoder signatures and their specificity margins                 |
| `reader_hygiene_test.go` in that directory                         | Emission, captured-fragment timing and direction across registered readers |
| `internal/decoder/core` fragment index                             | Map byte offsets back to captured fragments                                |
| Collector corpus/regression tests                                  | Record output and worker/replay invariance                                 |

A decoder change must keep selecting the decoder with the strongest signature and must keep each message's provenance. See [testing](tests.md) for corpus prerequisites and skipped tests.
