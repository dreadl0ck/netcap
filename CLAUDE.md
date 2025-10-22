# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

**Build main binary:**
```bash
go build -o net ./cmd/
```

**Build with specific flags (from go.mod):**
```bash
go build -ldflags "-X main.version=$(git describe --tags --always)" -o net ./cmd/
```

**Test commands:**
```bash
go test ./...                    # Run all tests
go test -v ./types/              # Run specific package tests with verbose output
go test -bench=. ./encoder/      # Run benchmarks for encoder package
```

## High-Level Architecture

Netcap is a network packet analysis framework that converts network traffic into structured audit records using Protocol Buffers. The architecture is organized into several key components:

### Core Components

**Command Structure (`cmd/`):**
- Single binary with multiple subcommands: `capture`, `dump`, `label`, `collect`, `agent`, `proxy`, `export`, `transform`, `util`
- Main entry point at `cmd/main.go` routes to subcommand handlers
- Each subcommand has its own package with `main.go`, `flags.go`, and `utils.go`

**Packet Processing Pipeline:**
1. **Collector (`collector/`)** - Handles live capture and PCAP file reading
2. **Decoder (`decoder/`)** - Converts raw packets to structured data
   - `packet/` - Individual packet decoders for each protocol
   - `stream/` - TCP stream reassembly and stream-based decoders
3. **Types (`types/`)** - Protocol Buffer definitions for all audit record types
4. **IO (`io/`)** - Output writers (protobuf, CSV, JSON, Elasticsearch)

**Key Architectural Patterns:**
- **Concurrent Processing**: Configurable worker pools with packet buffering
- **Stream Reassembly**: TCP stream reconstruction in `reassembly/` package
- **Protocol Extensibility**: Easy to add new protocol decoders
- **Multiple Output Formats**: Protocol Buffers (default), CSV, JSON, null sink

### Important Directories

- `types/` - Protocol Buffer audit record definitions (58 types total)
- `decoder/packet/` - Individual protocol packet decoders
- `decoder/stream/` - TCP stream-based protocol decoders
- `collector/` - Core packet collection and processing engine
- `reassembly/` - TCP stream reassembly implementation
- `io/` - Output format writers and file utilities
- `resolvers/` - DNS, GeoIP, MAC address, and other enrichment resolvers
- `maltego/` - Maltego OSINT platform integration transforms

### Testing and Development

**Performance Testing:**
- Use `zeus/scripts/test-params.sh` to benchmark different configuration combinations
- Test various worker counts, buffer sizes, compression settings, and decoder selections

**Common Development Tasks:**
- Add new protocol decoders in `decoder/packet/` and `decoder/stream/`
- Protocol Buffer definitions in `types/` with corresponding `.proto` files
- Update `cmd/main.go` to add new subcommands
- IO writers are in `io/` for new output formats

### Configuration Notes

- Worker count defaults to number of CPU cores
- Packet buffer size (`-pbuf`) affects memory usage and performance
- TCP reassembly can be disabled for performance with `-reassemble-connections false`
- Deep Packet Inspection (DPI) available via `-dpi` flag
- Multiple database integrations: Elasticsearch, Prometheus metrics, GeoIP, MAC vendors

### Key Performance Flags

- `-workers N` - Number of worker goroutines
- `-pbuf N` - Packet buffer size per worker
- `-compression-level` - Compression settings (none, max-speed, max-compression)
- `-flushevery N` - TCP assembler flush interval
- `-include/-exclude` - Decoder selection for performance tuning