# Testing

The root `Makefile` defines the test targets. List them with `make test-help`. Build tags and native dependencies must match the feature you test.

## Prerequisites

Use the Go version in `go.mod` and install the native dependencies described in [installation](installation.md). Integration and corpus tests may need external captures and are skipped when a capture is missing, so read the skip messages.

## Unit Tests

```sh
make test-unit
make test-pkg PKG=./internal/collector/
```

`test-unit` runs `go test -short -race -coverprofile=coverage.out ./...`. To build without native dependencies, pass tags:

```sh
GOWORK=off go test -tags nodpi,noyara ./internal/delimited ./types
```

Run the package you changed and its regression tests first, then the wider suite.

## Capture regressions

| Command                 | Scope                                                               |
| ----------------------- | ------------------------------------------------------------------- |
| `make test-all`         | Unit, integration and regression entrypoints                        |
| `make test-e2e`         | Tagged CLI workflow tests                                           |
| `make test-determinism` | Ultimate PCAP worker-count invariance and repeatability             |
| `make test-wireshark`   | Checksum-pinned Wireshark corpus; NetMon conversion needs `editcap` |

Determinism checks compare the complete output, not only record counts. Set `NETCAP_REQUIRE_ULTIMATE_PCAP=1` (the determinism target does) to make a missing capture fail the run instead of skipping. The fetch recipes are in `scripts/` and `zeus/`; use them rather than a capture that only has the same name.

## Benchmarks

```sh
GOWORK=off go test -tags nodpi,noyara -run '^$' -bench '^BenchmarkInitRecord' -benchmem ./internal/netio
```

This reports `BenchmarkInitRecordFirst` and `BenchmarkInitRecordLast`. `internal/delimited` has no benchmarks. Record the hardware, Go version, build tags and corpus hash with your results, and compare completeness and resource use as well as throughput.

## Race Detection Tests

```sh
make test-race
```

The race detector slows the run and needs more memory. It covers Go code only; native analyzers need their own sanitizer runs.
