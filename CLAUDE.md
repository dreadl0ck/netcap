# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build main binary (CGO required for libpcap)
go build -o net ./cmd/

# Build with version info
go build -ldflags "-X github.com/dreadl0ck/netcap.Version=$(git describe --tags --always)" -o net ./cmd/

# Build without DPI support (fewer C dependencies)
go build -tags=nodpi -o net ./cmd/

# Service mode with hot reload (requires air: go install github.com/air-verse/air@latest)
air
```

## Testing

```bash
# Unit tests (default, fast)
make -f Makefile.test test-unit

# All tests: unit + integration + regression
make -f Makefile.test test-all

# Test a specific package
make -f Makefile.test test-pkg PKG=./collector/
go test -v -run TestSpecificFunc ./collector/

# Integration tests (require test fixtures/PCAPs)
make -f Makefile.test test-integration

# Race detector
make -f Makefile.test test-race

# Benchmarks (outputs cpu.prof and mem.prof)
make -f Makefile.test test-bench

# Coverage with 80% threshold enforcement
make -f Makefile.test test-coverage-check

# Update golden files after intentional output changes
make -f Makefile.test test-golden-update
```

## Linting

```bash
golangci-lint run
```

Key settings in `.golangci.yml`:
- Line length limit: 300 chars
- Function limits: 20 cyclomatic complexity, 125 lines, 60 statements
- Imports: `goimports` with local prefix `github.com/dreadl0ck/netcap`
- Test files excluded from linting (TODO to enable)
- `sshx/` and `tls/` directories skipped
- `issues-exit-code: 0` (not yet enforced)

## Go Workspace

The project uses `go.work` referencing a local `../go-dpi` dependency. Ensure `github.com/dreadl0ck/go-dpi` is cloned as a sibling directory for DPI features.

## High-Level Architecture

Netcap converts network traffic (live capture or PCAP files) into structured Protocol Buffer audit records. Module path: `github.com/dreadl0ck/netcap`.

### Processing Pipeline

1. **Collector** (`collector/`) — reads packets from live interfaces or PCAP files, distributes to worker pool
2. **Decoder** (`decoder/`) — converts raw packets to typed audit records
   - `decoder/packet/` — 75+ individual protocol decoders (one per protocol layer)
   - `decoder/stream/` — 40+ TCP stream-based decoders (TLS, SSH, QUIC, SMB, etc.)
   - `decoder/config/` — decoder selection via `-include`/`-exclude` flags
3. **Types** (`types/`) — all 58 audit record types defined in `netcap.proto`, generated with `protoc-gen-gogo`
4. **IO** (`io/`) — output writers: Protocol Buffers (default), CSV, JSON, Elasticsearch
5. **Reassembly** (`reassembly/`) — TCP stream reconstruction
6. **Resolvers** (`resolvers/`) — enrichment: DNS, GeoIP, MAC vendor lookup
7. **DPI** (`dpi/`) — optional Deep Packet Inspection via nDPI/libprotoident (requires CGO)

### Command Structure

Single binary (`cmd/main.go`) with subcommands via `urfave/cli/v3`: `capture`, `dump`, `label`, `collect`, `agent`, `proxy`, `export`, `transform`, `util`, `inject`, `split`. Each subcommand is its own package under `cmd/` with `main.go`, `flags.go`, `utils.go`.

### Service Mode

The `capture` subcommand supports `--service` mode serving an HTTP API with a Next.js frontend at `cmd/capture/webui/frontend/` (pnpm-based). Use `air` for hot-reload during development.

### Version Variables

`version.go` at root defines `Version`, `Commit`, and `GopacketVersion` — overridable via `-ldflags` at build time.

### Proto Code Generation

All types are defined in `netcap.proto` and generated to `types/netcap.pb.go` using `protoc-gen-gogo`. There are no `go:generate` directives — proto compilation is manual.

### Key Directories

- `internal/` — ja4 TLS fingerprinting, logger, metrics, filter, helpers
- `maltego/` — Maltego OSINT platform integration transforms
- `configs/` — YAML configs for file extraction, firewall rules, harvesters
- `rules/examples/` — YAML detection rule definitions
- `zeus/scripts/` — build and performance testing scripts
