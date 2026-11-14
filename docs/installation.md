# Installation

Download the archive for your operating system and architecture from the [v0.16.6 release](https://github.com/dreadl0ck/netcap/releases/tag/v0.16.6). Keep the `net` executable and its `lib/` directory together.

## Binary Distributions

| Distribution        | Requirements                                                                                                        |
| ------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Linux libc          | Debian/Ubuntu or compatible. Keep `net`, `lib/net.bin` and the bundled loader and libraries together.               |
| Linux musl          | Alpine or compatible. Use this archive, not the libc one.                                                           |
| macOS DPI           | macOS 26 or later. Keep the `lib/` directory next to the executable.                                                |
| macOS nodpi         | macOS 15 or later. No native DPI classification.                                                                    |
| Windows amd64 nodpi | Offline analysis without a driver, no YARA-X. Live capture and BPF filters need Npcap and are untested.             |
| Standalone firewall | `netcap-firewall-v0.16.6-linux-{amd64,arm64}.tar.gz`. A separate archive that does not include the capture runtime. |

On Linux the `net` wrapper loads its own runtime and installs nothing into system directories. Both macOS variants are Developer ID signed and notarized. Checksums are published with each release.

```sh
net --version
net capture -h
```

`net --version` should show the version you just installed. If it does not, an older `net` earlier in your `PATH` is taking priority. Continue with [First capture](quickstart.md).

## Homebrew

```sh
brew tap dreadl0ck/formulas
brew install netcap
net --version
```

The formula installs the full native runtime under `libexec`. The tap can be newer than v0.16.6, so note the output of `net --version` when you report or reproduce results.

## Go Get

`go get` does not install the current executables. Clone the release and build the embedded browser assets before compiling the Go code, as described below.

## Manual Build

You need the Go version declared in `go.mod`, Node and pnpm for the UI, a C toolchain and the libpcap headers. Native DPI and YARA need additional libraries. This reduced build leaves both out:

```sh
git clone --branch v0.16.6 https://github.com/dreadl0ck/netcap.git
cd netcap/cmd/capture/webui/frontend
pnpm install --frozen-lockfile
pnpm build
cd ../../../..
GOWORK=off go build -tags nodpi,noyara -o net ./cmd/net
./net --version
```

`nodpi` still needs libpcap. Run the result as `./net` so an older executable in your `PATH` is not picked up.

## Reproducible Builds via Go Modules

`go.mod` and `go.sum` pin the module dependencies. For an identical build, also record the source commit, the Go and C toolchains, the build tags, the embedded UI and the native libraries. Set `GOWORK=off` to ignore local workspace replacements.

## Development Build

To build current `master`, check out the commit you want instead of the `v0.16.6` tag in the recipe above, then rebuild the UI and the Go binary together. `net COMMAND -h` shows the flags of the executable you built.

The standalone firewall is CGO-free and builds without the capture UI or native dependencies. Follow its [quickstart](APPLICATION_FIREWALL.md#quickstart). For native capture images, use the [matched builder/runtime](docker-containers.md) recipes. Do not mix the YARA-X Go bindings with an older C library.

See [macOS development](macos-development-setup.md) for platform tooling and [testing](tests.md) for running the tests. Schema generation needs `protoc-gen-gogofaster`; you only need it if you change the schema.

## Cross Compilation

CGO and the native dependencies mean that setting `GOOS` and `GOARCH` is not enough. Use the platform build recipes in `zeus/scripts/` with the matching C compiler, headers and runtime, then test the result on the target OS.

## Buildsystem

[Zeus](https://github.com/dreadl0ck/zeus) drives builds and releases through `zeus/commands.yml`. The root Makefile has the test targets. Run `zeus` without arguments to list the available commands.

## Optional enrichment

```sh
net util -download-dbs
net util -update-dbs
```

Signed clients verify the publisher metadata. The databases go to `~/.config/netcap/dbs`; set `NC_CONFIG_ROOT` to change the parent directory. See [database updates](database-updates.md) for trust and sources. Analysis works without them.
