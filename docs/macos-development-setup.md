# macOS Development Setup

Build the public Go checkout with the Go version in `go.mod`, Xcode command-line
tools, libpcap headers and the embedded browser assets. Prebuilt release runtime
requirements are listed in [installation](installation.md).

## Prerequisites

With Homebrew already installed:

```sh
brew install go libpcap node pnpm
go version
pnpm --version
```

Confirm the Go version satisfies `go.mod`; the old “Go 1.21 or later” minimum
does not describe v0.15.2. Use the checkout's declared package-manager version
when building the UI.

## Clone and Build Netcap

Follow the tagged [manual build](installation.md#manual-build) to build the UI
and a `nodpi,noyara` executable. Those tags disable optional native DPI/YARA,
not libpcap. Building full DPI requires the matching native runtime dependencies
and recipes in `zeus/scripts/`.

Use `./net --version` to inspect the resulting binary. A build to the project
directory does not replace another `net` already installed in `PATH`.

## Generate Protocol Buffers

An unchanged checkout includes generated Go bindings. Only install generators
when changing `types/netcap.proto`:

```sh
brew install protobuf
go install github.com/gogo/protobuf/protoc-gen-gogofaster@v1.3.2
export PATH="$(go env GOPATH)/bin:$PATH"
protoc --version
protoc --proto_path=types --gogofaster_out=types/. types/netcap.proto
```

Check the checkout's gogo version with `go list -m github.com/gogo/protobuf`
before changing generator pins. `zeus gen-proto-dev` wraps Go generation.
Swift/JavaScript plugins are only needed when deliberately generating those
bindings; they are not prerequisites for a normal Go build.

## Environment Variables

Use `GOWORK=off` for release-like builds. A local `go.work` can silently replace
the pinned go-dpi module with a sibling checkout. `NC_CONFIG_ROOT` controls local
runtime data separately; see [configuration](configuration.md).

## Troubleshooting

| Error | Check |
| --- | --- |
| Missing embedded frontend files | Build `cmd/capture/webui/frontend` first |
| `pcap.h` or linker error | C toolchain/libpcap and matching architecture |
| `protoc-gen-gogofaster` missing | Go binary directory in `PATH` |
| Unexpected large generated diff | Generator version/options; use `gogofaster`, not `gogo` |
| Linter refuses Go version | Linter was built with an older Go toolchain than the module requires |

Run [scoped tests](tests.md); format only changed Go files. Follow
[extension](extension.md) for decoder registration and schema contracts.
