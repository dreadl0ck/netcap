# Adding decoders

Per-packet decoders go in `internal/decoder/packet`. TCP/UDP conversation decoders go in `internal/decoder/stream`. Copy the structure of an existing decoder of the same kind.

## Example: a line-based protocol (IRC)

The IRC decoder in `internal/decoder/stream/irc/` is a good template for a text protocol with one message per line.

| Step                   | File                 | What it does                                                                                                                                                                                                |
| ---------------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Define the record   | `types/netcap.proto` | `message IRC` with `Timestamp`, addresses and ports, `Prefix`, `Command`, `Parameters`, `Message`; a `NC_IRC` type in the enum                                                                              |
| 2. Declare the decoder | `irc/irc.go`         | `Decoder` with `Type`, `Name`, `Description`, `Specificity`, `CanDecode`, `Factory` and `Typ: core.TCP`                                                                                                     |
| 3. Parse the stream    | `irc/irc_reader.go`  | `Decode` runs one function per direction. `readMessage` reads a line with `ReadString('\n')`, splits `[:prefix] COMMAND params` and writes a record with the timestamp of the packet where the line started |
| 4. Map a default port  | `stream/stream.go`   | `6667: irc.Decoder` in `DefaultStreamDecoders`                                                                                                                                                              |
| 5. Test                | `irc/irc_test.go`    | `CanDecode` accepts IRC traffic and rejects binary data                                                                                                                                                     |

`CanDecode` receives the client and server bytes of a conversation. It matches the shape of a server reply (a line starting with `:` that contains `001` or `NOTICE`) or a client `NICK`, not a bare substring. A bare substring such as `001` would match binary traffic and take over every conversation on port 6667.

## Protocol Buffer Definitions

Add a message to `types/netcap.proto` and, if needed, a unique `NC_` type in the enum. Keep existing field and enum numbers, and reserve numbers you remove. Timestamps are `int64` Unix nanoseconds.

Generate the Go code with the `gogofaster` plugin:

```sh
zeus gen-proto-dev
```

This runs `protoc --proto_path=types --gogofaster_out=types/. types/netcap.proto`. Use the generator version pinned by the checkout and review the generated diff. Use `gogofaster`, not `gogo`.

## Encoder Implementation

| Decoder kind            | Example                                 | Registration/behavior to inspect                             |
| ----------------------- | --------------------------------------- | ------------------------------------------------------------ |
| Packet layer            | `internal/decoder/packet/arp.go`        | `newGoPacketDecoder`, typed handler, registered layer/type   |
| Custom packet/aggregate | `internal/decoder/packet/connection.go` | Initialization, concurrency, bounded state and finalization  |
| TCP/UDP stream          | `internal/decoder/stream/`              | Selector specificity, framing, directions, gaps and teardown |

In the ARP decoder, `decodeARP(*layers.ARP, int64)` returns a protobuf message. Import `github.com/gopacket/gopacket` and `github.com/gogo/protobuf/proto`.

Stream parsers must check buffered lengths before allocating, tell unsupported content apart from malformed framing, and keep gap and completeness information. A port number alone is not enough to pick a parser for an ambiguous protocol.

## Audit Record Interface Implementation

Implement the `types.AuditRecord` interface in `types/audit_record.go`: CSV header and values, `Time() int64`, endpoints, metrics, JSON, packet context, encoding, analysis and `NetcapType()`.

Make sure CSV headers match the values, nested fields render consistently, byte fields have a defined representation and `SetPacketContext` updates the record pointer.

## Add Initializer

Register the message in `internal/netio.InitRecord` and in the decoder registry. Then check that `dump -header`, `-fields`, `-json` and CSV output all work on a capture that contains the protocol. Add browser/API rendering only if the record is shown there.

## Verification

Write tests for valid input, partial framing, oversized lengths, retransmissions and gaps, and unsupported input. Assert on the records and health files that come out, not only that nothing panics. Run the affected packages and the relevant [capture regressions](tests.md), including worker invariance if the decoder keeps shared state.
