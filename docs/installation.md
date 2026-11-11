# Installation

These instructions target the public Go release
[v0.16.5](https://github.com/dreadl0ck/netcap/releases/tag/v0.16.5).
Its source revision is recorded in the release's `release-qualification.json`.
Start with an archive matching your operating system, architecture and native
runtime; keep the archive's executable and libraries together.

## Binary Distributions

| Distribution | Runtime requirement |
| --- | --- |
| Linux libc | Debian/Ubuntu-compatible runtime; retain `net`, `lib/net.bin` and bundled loader/libraries |
| Linux musl | Alpine-compatible runtime; use the musl archive rather than the libc archive |
| macOS DPI | macOS 26+; retain adjacent `lib/` native libraries |
| macOS nodpi | macOS 15+; no native DPI classification |
| Windows amd64 nodpi | Driver-free offline client; YARA-X excluded. Live capture/BPF workflows require compatible Npcap and remain unqualified |
| Standalone firewall | Separate `netcap-firewall-v0.16.5-linux-{amd64,arm64}.tar.gz` archives; not the capture runtime |

Linux wrappers load their private runtime; they do not install libraries into
system directories. macOS libraries use executable-relative install names.
Full supplier sources/build recipes accompany the macOS runtime asset.
Both macOS CLI variants are Developer ID signed and notarized; native execution
was qualified on macOS 26.6.2. The nodpi 15.0 minimum does not certify full
BPF/YARA operation on a clean macOS 15 machine. Windows Npcap runtime operation
also remains uncertified. See the release's checksums and qualification receipts.

```sh
net --version
net capture -h
```

Check that `net --version` resolves the intended executable and reports the
expected commit/DPI status. A previously installed `net` elsewhere in `PATH` can
hide the new archive. Continue with the [synthetic first capture](quickstart.md).

## Homebrew

```sh
brew tap dreadl0ck/formulas
brew install netcap
net --version
```

The formula installs its complete native runtime under `libexec`. The tap may
advance beyond the release documented here; record the installed version when
reproducing results.

## Go Get

`go get` manages dependencies; it does not install current Go executables.
Clone the release and build its embedded browser assets before compiling Go.

## Manual Build

Install the Go version declared in `go.mod`, Node/pnpm for the UI, a C toolchain
and libpcap headers. Native DPI and YARA require additional libraries; the
following reduced build disables those two optional integrations:

```sh
git clone --branch v0.16.5 https://github.com/dreadl0ck/netcap.git
cd netcap/cmd/capture/webui/frontend
pnpm install --frozen-lockfile
pnpm build
cd ../../../..
GOWORK=off go build -tags nodpi,noyara -o net ./cmd/net
./net --version
```

This is a source build, not the packaged runtime distribution. `nodpi` does not
remove libpcap requirements. Run it as `./net` so an older executable in `PATH`
cannot be selected accidentally.

## Reproducible Builds via Go Modules

`go.mod`/`go.sum` pin module dependencies. Reproduction also requires a recorded
source commit, Go/C toolchains, build tags, embedded UI and native libraries.
Use `GOWORK=off` to avoid local workspace replacements. Dependency pinning alone
does not prove bit-for-bit reproducibility.

## Development Build

For current `master` features, check out the exact reviewed commit instead of
the `v0.16.5` tag in the build recipe above, then rebuild the embedded UI and Go
binary together. v0.16.2 already includes `-incremental-http`,
`-capture-time-idle-expiry` and the three retained-state controls; check
`investigate -h` for `deliver-alerts`, and `split -h` for inspection/sharding.
These features do not require a development build; installed help remains the
reference for the selected executable.

The CGO-free standalone firewall builds independently of the capture UI/native
dependencies; follow its [quickstart](APPLICATION_FIREWALL.md#quickstart).
For native capture images, use the [matched builder/runtime](docker-containers.md)
recipes rather than mixing YARA-X Go bindings with an older C library.

Follow [macOS development](macos-development-setup.md) for platform tooling and
[testing](tests.md) for scoped verification. Schema generation uses
`protoc-gen-gogofaster`; it is unnecessary for an unchanged release checkout.

## Cross Compilation

CGO and native dependencies mean `GOOS`/`GOARCH` alone are insufficient. Use
the platform build recipes in `zeus/scripts/` and supply the matching C compiler,
headers and runtime. Verify the resulting archive on its target OS.

## Buildsystem

[Zeus](https://github.com/dreadl0ck/zeus) drives builds/releases through
`zeus/commands.yml`; the root Makefile provides test entrypoints. Run `zeus`
without arguments to inspect available commands.

## Optional enrichment

```sh
net util -download-dbs
net util -update-dbs
```

Signed clients verify publisher metadata. The default data directory is
`~/.config/netcap/dbs`; `NC_CONFIG_ROOT` changes its parent. Follow
[database updates](database-updates.md) for trust, source inventory and retired
catalogues. Packet-only analysis can proceed without this optional enrichment.
