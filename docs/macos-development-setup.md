# macOS development

You need the Go version from `go.mod`, the Xcode command-line tools, the libpcap headers and the embedded browser assets. Runtime requirements for prebuilt releases are in [installation](installation.md).

## Prerequisites

With Homebrew installed:

```sh
brew install go libpcap node pnpm
go version
pnpm --version
```

Check that the Go version satisfies `go.mod`, and use the package-manager version the checkout declares when you build the UI.

## Clone and Build Netcap

Follow the [manual build](installation.md#manual-build) to build the UI and a `nodpi,noyara` executable. Those tags turn off the optional native DPI and YARA support; libpcap is still required. A full DPI build needs the native runtime dependencies and the recipes in `zeus/scripts/`.

Check the result with `./net --version`. The build lands in the project directory and does not replace a `net` that is already in your `PATH`.

## Generate Protocol Buffers

The checkout includes the generated Go bindings. Install the generators only if you change `types/netcap.proto`:

```sh
brew install protobuf
go install github.com/gogo/protobuf/protoc-gen-gogofaster@v1.3.2
export PATH="$(go env GOPATH)/bin:$PATH"
protoc --version
protoc --proto_path=types --gogofaster_out=types/. types/netcap.proto
```

Before you change a generator pin, check the checkout's gogo version with `go list -m github.com/gogo/protobuf`. `zeus gen-proto-dev` wraps the Go generation. You only need the Swift and JavaScript plugins if you generate those bindings.

## Environment Variables

Set `GOWORK=off` for release-like builds. A local `go.work` can replace the pinned go-dpi module with a sibling checkout without any warning. `NC_CONFIG_ROOT` sets where local runtime data is stored; see [configuration](configuration.md).

## Troubleshooting

| Error                           | Check                                                                |
| ------------------------------- | -------------------------------------------------------------------- |
| Missing embedded frontend files | Build `cmd/capture/webui/frontend` first                             |
| `pcap.h` or linker error        | C toolchain, libpcap and matching architecture                       |
| `protoc-gen-gogofaster` missing | Go binary directory in `PATH`                                        |
| Unexpected large generated diff | Generator version and options; use `gogofaster`, not `gogo`          |
| Linter refuses Go version       | Linter was built with an older Go toolchain than the module requires |

Run the [tests](tests.md) for the packages you changed and format only the Go files you changed. [Adding decoders](extension.md) covers decoder registration and schema changes.
