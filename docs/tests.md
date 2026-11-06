# Unit Tests

The root `Makefile` defines test entrypoints; build tags and native dependencies
must match the feature being tested. List targets with `make test-help`.

## Prerequisites

Use the Go version in `go.mod` and install native dependencies as described in
[installation](installation.md). Integration/corpus tests may need external
captures. A skipped corpus test is not evidence that its assertions passed.

## Unit Tests

```sh
make test-unit
make test-pkg PKG=./internal/collector/
```

`test-unit` runs `go test -short -race -coverprofile=coverage.out ./...`.
For a reduced native-dependency build, choose explicit tags:

```sh
GOWORK=off go test -tags nodpi,noyara ./internal/delimited ./types
```

Run the affected package and meaningful regression fixtures before broadening
the suite. Review the actual assertions and skip messages; historical pasted
test output does not describe the current suite.

## Documentation qualification

```sh
make docs-check NETCAP_BIN=/absolute/path/to/net
```

Python 3 and Bash are required. The checker reads runnable blocks directly from
the [investigation](investigation-walkthrough.md) and baseline guides, creates
offline fixtures in a fresh temporary workspace, and checks positive and benign
rule cases, extracted bytes, evidence export, configuration parsing and baseline
approval/restart. It also validates navigation, Markdown targets and shell
syntax. It never sends captured packets.

`make docs-source-check` checks protobuf field excerpts, compiles concrete YAML
examples without overriding their `enabled` state and tests representative
positive/negative expressions.
Run source checks with the build tags appropriate for the installed libraries.
`make test-golden-update` is retired: no golden-update suite exists, and the
target now fails explicitly instead of printing a misleading success message.

`.github/workflows/documentation.yml` runs these contracts and the marked lab
on documentation/source changes. It builds current source with optional native
analyzers disabled; release qualification additionally uses the actual release
binary through `NETCAP_BIN`.

## Capture regressions

| Command | Scope |
| --- | --- |
| `make test-all` | Unit, integration and regression entrypoints |
| `make test-e2e` | Tagged CLI workflow tests |
| `make test-determinism` | Required Ultimate PCAP worker-count invariance and repeatability |
| `make test-wireshark` | Checksum-pinned Wireshark corpus; NetMon conversion needs `editcap` |

Determinism checks compare complete output, not just total record counts. Use
`NETCAP_REQUIRE_ULTIMATE_PCAP=1` (as the determinism target does) when a missing
fixture must fail qualification instead of skip. Fetch recipes live in
`scripts/` and `zeus/`; do not substitute an unverified capture with the same name.

## Benchmarks

```sh
GOWORK=off go test -tags nodpi,noyara -run '^$' -bench '^BenchmarkInitRecord' -benchmem ./internal/netio
```

Expect `BenchmarkInitRecordFirst` and `BenchmarkInitRecordLast` measurements.
`internal/delimited` currently has no benchmarks; an exit-zero command with no
`Benchmark…` rows is not a measurement. Record hardware, Go version, build tags
and corpus hash. A record-initializer
microbenchmark is not end-to-end live capture capacity. Compare completeness
and resource use alongside throughput.

## Race Detection Tests

```sh
make test-race
```

Race instrumentation changes timing and memory demand. Native analyzers may
need separate sanitizer qualification; a Go race pass covers only exercised
instrumented paths.
