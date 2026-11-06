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

## Capture regressions

| Command | Scope |
| --- | --- |
| `make test-all` | Unit, integration and regression entrypoints |
| `make test-e2e` | Tagged CLI workflow tests |
| `make test-determinism` | Required Ultimate PCAP worker-count invariance and repeatability |
| `make test-wireshark` | Checksum-pinned Wireshark corpus; NetMon conversion needs `editcap` |
| `make test-golden-update` | Rewrite expected outputs after an intentional reviewed behavior change |

Determinism checks compare complete output, not just total record counts. Use
`NETCAP_REQUIRE_ULTIMATE_PCAP=1` (as the determinism target does) when a missing
fixture must fail qualification instead of skip. Fetch recipes live in
`scripts/` and `zeus/`; do not substitute an unverified capture with the same name.

## Benchmarks

```sh
GOWORK=off go test -tags nodpi,noyara -run '^$' -bench=. -benchmem ./internal/delimited
```

Record hardware, Go version, build tags and corpus hash. A packet-reader
microbenchmark is not end-to-end live capture capacity. Compare completeness
and resource use alongside throughput.

## Race Detection Tests

```sh
make test-race
```

Race instrumentation changes timing and memory demand. Native analyzers may
need separate sanitizer qualification; a Go race pass covers only exercised
instrumented paths.
