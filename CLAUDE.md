# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build main binary (CGO required for libpcap)
go build -o net ./cmd/net/

# Build with version info
go build -ldflags "-X github.com/dreadl0ck/netcap.Version=$(git describe --tags --always)" -o net ./cmd/net/

# Build without DPI support (fewer C dependencies)
go build -tags=nodpi -o net ./cmd/net/

# Build with Hyperscan/Vectorscan acceleration (multi-pattern regex prefilter
# for nmap service probes). Requires libhs via pkg-config — install
# `vectorscan` (macOS/ARM) or `libhyperscan-dev` (Linux x86_64).
CGO_ENABLED=1 go build -tags hyperscan -o net ./cmd/net/

# Service mode with hot reload (requires air: go install github.com/air-verse/air@latest)
air
```

## Testing

```bash
# Unit tests (default, fast)
make test-unit

# All tests: unit + integration + regression
make test-all

# Test a specific package
make test-pkg PKG=./internal/collector/
go test -v -run TestSpecificFunc ./internal/collector/

# Integration tests (require test fixtures/PCAPs)
make test-integration

# Race detector
make test-race

# Benchmarks (outputs cpu.prof and mem.prof)
make test-bench

# Coverage with 80% threshold enforcement
make test-coverage-check

# Update golden files after intentional output changes
make test-golden-update
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
- `tls/` directories skipped, which silently excludes `internal/decoder/stream/tls/` (10 files) from both linting and formatting. The `sshx/` exclusion beside it matched no directory in the repo and was removed
- `golangci-lint` is not wired into CI or the Makefile; it runs only via `zeus lint`. 285 files are not `goimports -local`-clean and 81 are not `gofmt`-clean, so a full run is not currently green
- `issues-exit-code: 0` (not yet enforced)

## Go Workspace

The project uses `go.work` referencing a local `../go-dpi` dependency. Ensure `github.com/dreadl0ck/go-dpi` is cloned as a sibling directory for DPI features.

## High-Level Architecture

Netcap converts network traffic (live capture or PCAP files) into structured Protocol Buffer audit records. Module path: `github.com/dreadl0ck/netcap`.

### Processing Pipeline

1. **Collector** (`internal/collector/`) — reads packets from live interfaces or PCAP files, distributes to worker pool
2. **Decoder** (`internal/decoder/`) — converts raw packets to typed audit records
   - `internal/decoder/packet/` — 75+ individual protocol decoders (one per protocol layer)
   - `internal/decoder/stream/` — 40+ TCP stream-based decoders (TLS, SSH, QUIC, SMB, etc.)
   - `internal/decoder/config/` — decoder selection via `-include`/`-exclude` flags
3. **Types** (`types/`) — all 58 audit record types defined in `proto/netcap.proto`, generated with `protoc-gen-gogo`
4. **IO** (`internal/netio/`, package `netio`) — output writers: Protocol Buffers (default), CSV, JSON, Elasticsearch
5. **Reassembly** (`internal/reassembly/`) — TCP stream reconstruction
6. **Resolvers** (`internal/resolvers/`) — enrichment: DNS, GeoIP, MAC vendor lookup
7. **DPI** (`internal/dpi/`) — optional Deep Packet Inspection via nDPI/libprotoident (requires CGO)

### Package Layout

Library code lives under `internal/`. Only three import paths are public, because
only those are consumed from outside the module — by `netcap-pro`, the sole
external consumer: the root package `github.com/dreadl0ck/netcap` for `Version`
and the licence embed, `defaults/`, and `cmd/capture/webui/`. `types/` also stays
at the root — nothing external imports it, but it ships as source in all three
`.goreleaser` archives.

Adding a library package means adding it under `internal/`, not at the root.

### Command Structure

Single binary (`cmd/net/main.go`) with subcommands via `urfave/cli/v3`: `capture`, `dump`, `label`, `collect`, `agent`, `proxy`, `export`, `transform`, `util`, `inject`, `split`. Each subcommand is its own package under `cmd/` with `main.go`, `flags.go`, `utils.go`. Note `split` is not registered in `cmd/net/main.go` despite being documented; see the findings in the git history.

### Service Mode

The `capture` subcommand supports `--service` mode serving an HTTP API with a Vite + React 19 single-page frontend at `cmd/capture/webui/frontend/`. The frontend is a pnpm workspace containing:

- the app shell (root `package.json`, built with Vite, tested with Vitest)
- a reusable UI library `@dreadl0ck/netcap-ui` at `cmd/capture/webui/frontend/packages/netcap-ui/` (built with tsup)

Client-side routing uses `react-router` v7; data fetching uses `swr`; UI is MUI 7 + Emotion. There is no Next.js, no SSR, and no `middleware.js`/`proxy.js`. Use `air` for Go hot-reload during development; use `pnpm dev` inside the frontend directory for the UI dev server.

### Version Variables

`version.go` at root defines `Version`, `Commit`, and `GopacketVersion` — overridable via `-ldflags` at build time.

### Proto Code Generation

All types are defined in `proto/netcap.proto` and generated to `types/netcap.pb.go` using `protoc-gen-gogo`. There are no `go:generate` directives — proto compilation is manual.

### Key Directories

- `internal/` — every library package: collector, decoder, netio, reassembly, resolvers, dpi, maltego, rules, label, dbs, encoder, utils, injection, firewall, magika, analyze, plus ja4, logger, metrics, filter, mcp, table
- `internal/maltego/` — Maltego OSINT platform integration transforms
- `configs/` — YAML configs for file extraction, firewall rules, harvesters
- `internal/rules/examples/` — YAML detection rule definitions
- `proto/` — `netcap.proto`, the schema for `types/`
- `init/` — systemd unit
- `scripts/` — shell helpers, bash completion, and the Python DNN research code under `scripts/analyze-dnn/`
- `zeus/scripts/` — build and performance testing scripts
