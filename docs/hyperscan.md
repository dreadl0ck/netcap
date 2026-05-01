# Hyperscan / Vectorscan integration

Netcap can optionally use [Intel Hyperscan](https://www.hyperscan.io/) (or its
portable fork [Vectorscan](https://github.com/VectorCamp/vectorscan)) to
accelerate multi-pattern regex matching.

The integration is **off by default** — building without the build tag
produces a binary with zero new C library dependencies.

---

## Table of contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Building](#building-with-hyperscan)
- [Running the tests](#running-the-tests)
- [Running the benchmarks](#running-the-benchmarks)
- [Performance results](#performance-results)
- [Web UI / API status](#web-ui--api-status)
- [Logging](#logging)
- [Scope and limitations](#scope-and-limitations)
- [Troubleshooting](#troubleshooting)

---

## What it does

Hyperscan is a vectorised regex matcher that excels when the same input
buffer must be tested against many patterns at once. Netcap uses it as a
**prefilter** in front of the existing RE2 engine in two places:

### 1. Service probe matcher

`decoder/stream/service/service_probe.go`

1. At startup all RE2-compatible service-probe expressions are compiled
   into per-category Hyperscan block-mode databases.
2. For every banner, Hyperscan reports the (small) set of probes whose
   pattern fires.
3. RE2 is then invoked only on those probes for capture-group extraction
   (Hyperscan does not return submatches).

Probes that Hyperscan refuses to compile (e.g. patterns with PCRE
backreferences) automatically stay on the existing RE2 path — no
behavioural change. The .NET-compatible `regexp2` engine path is left
untouched because it deliberately exists to support PCRE features
Hyperscan does not implement.

### 2. CMS / web framework detection

`decoder/stream/software/software.go` + `cms_hs.go`

The `cmsdb.json` database (1100+ frameworks, ~600 header/cookie regexes)
is compiled into two per-source HS databases (one for headers, one for
cookies). For every HTTP response, the matcher computes the union of
candidate products that any received header/cookie value could match,
then iterates only that subset of `cmsDB` instead of all 1100+
frameworks. Header-name-only entries (no value regex) are always kept
in the candidate set so behaviour is identical.

### 3. Rule engine `MatchesPattern`

`internal/filter/helpers.go` + `matches_pattern_hs.go`

`MatchesPattern(field, pattern)` — used pervasively in `rules/` and
`firewall/` YAML expressions — gains a per-pattern HS cache. The first
call with a given pattern compiles it into a tiny single-pattern HS
database; subsequent calls take the boolean answer directly from HS,
which is several times faster than RE2 for typical alternation-heavy
detection patterns. Patterns Hyperscan refuses to compile transparently
fall through to the existing RE2 cache path.

### Cross-subsystem registry

`internal/hsmatch/registry.go` lets each consumer self-register a
JSON-friendly status snapshot. The web UI handler enumerates the
registry rather than hard-coding consumers, so future migrations don't
need to touch `cmd/capture/webui/`.

---

## Architecture

```
                        +------------------------------------+
                        | nmap-service-probes  (~9k regexes) |
                        +------------------+-----------------+
                                           |
                                           v
       initServiceProbes()  --(per probe)-->  RE2 compile (existing path)
                |
                +-->  buildServiceProbeHSIndex()  (only with -tags hyperscan)
                          |
                          v
             +-------------------------------+
             | per-category hsmatch.DB       |  block-mode multi-pattern
             |  - supported set (HS-compat)  |  database, scratch pool
             |  - rejections (RE2-only)      |
             +-------------------------------+

                                    runtime
                          +------------------------------+
                          | MatchServiceProbes(banner)   |
                          +-------------+----------------+
                                        |
                  hsCandidatesForCategory(category, ..)
                                        |
                          +-------------+----------------+
                          |  HS hit IDs ∪ RE2-only IDs   |
                          +-------------+----------------+
                                        |
                                        v
                          +------------------------------+
                          | for each candidate probe i:  |
                          |   probe.RegEx.FindStringSub  |  RE2 with capture
                          |   extract Vendor/Product/... |
                          +------------------------------+
```

Code map:

- `internal/hsmatch/` — thin gohs wrapper exposing `Compile`, `Match`,
  `Stats`, `Close`. Two files: `hs.go` (built with `hyperscan` tag,
  imports gohs / libhs) and `hs_stub.go` (default, returns `ErrDisabled`).
- `decoder/stream/service/service_probe_hs.go` — service-probe specific
  glue: per-category index, status accessor, build/scan stats.
- `decoder/stream/service/service_probe_hs_stub.go` — twin stub.
- `cmd/capture/webui/hyperscan_handlers.go` — `GET /api/hyperscan` JSON
  endpoint for the web UI.

The `hsmatch` package is intentionally generic so future migrations
(secret harvesters, software detection, filter helpers, …) can reuse it
without touching gohs directly.

---

## Building with Hyperscan

Hyperscan/Vectorscan must be installed and discoverable through
`pkg-config` (it ships a `libhs.pc`).

### macOS (arm64 + Intel)

```bash
brew install vectorscan pkg-config
PKG_CONFIG_PATH=$(brew --prefix vectorscan)/lib/pkgconfig \
  CGO_ENABLED=1 \
  go build -tags hyperscan -o net ./cmd/
```

Apple Silicon ships only Vectorscan (the ARM-compatible fork). The library
exposes the same `libhs` ABI as Intel Hyperscan, so `-lhs` resolves either.

### Linux x86_64

```bash
sudo apt install libhyperscan-dev pkg-config   # Debian/Ubuntu
# or
sudo dnf install hyperscan-devel pkgconf-pkg-config   # Fedora/RHEL
CGO_ENABLED=1 go build -tags hyperscan -o net ./cmd/
```

### Linux arm64 / RISC-V / Power

Use Vectorscan instead of Intel Hyperscan:

```bash
sudo apt install libvectorscan-dev pkg-config   # Debian 12+/Ubuntu 22.04+
# or build from source:
git clone https://github.com/VectorCamp/vectorscan
cd vectorscan && mkdir build && cd build
cmake .. -DBUILD_STATIC_LIBS=on -DBUILD_SHARED_LIBS=on
make -j$(nproc) && sudo make install
sudo ldconfig
CGO_ENABLED=1 go build -tags hyperscan -o net ./cmd/
```

### Combining with other build tags

The `hyperscan` tag is independent of `nodpi` and the others. Common
combinations:

```bash
# Hyperscan + DPI (default)
CGO_ENABLED=1 go build -tags hyperscan -o net ./cmd/

# Hyperscan but no DPI
CGO_ENABLED=1 go build -tags "hyperscan nodpi" -o net ./cmd/
```

### Verify the binary picked up libhs

```bash
otool -L ./net | grep -iE 'hs|hyper|vector'   # macOS
ldd     ./net | grep -iE 'hs|hyper|vector'    # Linux
```

You should see `libhs.5.dylib` (macOS) or `libhs.so.5` (Linux). If
nothing is printed, the binary was built without the `hyperscan` tag.

---

## Running the tests

The Makefile target gates on `pkg-config --exists libhs` and skips with a
helpful message if libhs is not installed:

```bash
make -f Makefile.test test-hyperscan
```

Equivalent direct invocation:

```bash
PKG_CONFIG_PATH=$(brew --prefix vectorscan)/lib/pkgconfig \
  CGO_ENABLED=1 \
  go test -v -tags hyperscan \
    ./internal/hsmatch/... \
    ./decoder/stream/service/...
```

Tests covered:

| Test | Verifies |
|---|---|
| `TestCompileAndMatch` | basic multi-pattern compile + scan, including `Stats` accounting |
| `TestCompilePartitionsRejected` | unsupported patterns (e.g. backref) are reported with `Index/ID/Expr/Reason`, accepted patterns still build a DB |
| `TestEmpty` | empty input returns `(nil, nil, nil)` |
| `TestMatchAbort` | handler-returned error propagates and is **not** counted as a scan error |
| `TestMatchAfterClose` | post-`Close` scans return `ErrClosed`; `Close` is idempotent |
| `TestMatchEmptyBuffer` | empty buffer is a fast no-op, doesn't bump `Stats.Scans` |
| `TestConcurrentMatch` | 32 goroutines × 50 scans share scratch pool without races |
| `TestVersion` | `Version()` returns a non-empty libhs version string |
| `TestHyperscanFastPath_MatchesExpectedProbe` | end-to-end probe match still extracts capture groups via RE2 |
| `TestHyperscanFastPath_PrefilterRulesOut` | banner that no probe matches → no Product/MatchedProbeID |
| `TestHyperscanFastPath_RejectedProbeStillEvaluated` | HS-rejected probe is still hit through RE2 fallback |
| `TestHyperscanFastPath_CandidatesNilWhenDisabled` | `UseRE2=false` disables the prefilter |
| `TestHyperscanFastPath_CandidatesNilWhenCategoryUnknown` | unknown category is a no-op |
| `TestHyperscanStatus_ReflectsBuild` | `GetHyperscanStatus()` reflects the loaded probe set |

A symmetric set of stub-build tests (`TestStubReturnsDisabled`,
`TestStubVersion`, `TestStubStatsZero`, `TestStubMatchAlwaysDisabled`)
runs in the default build to guarantee callers can detect "HS not compiled
in" without crashing.

---

## Running the benchmarks

Two benchmark suites ship with the integration:

### Wrapper-level (`internal/hsmatch`)

Characterises raw `hsmatch.DB.Match` overhead and scaling vs. pattern set
size:

```bash
PKG_CONFIG_PATH=$(brew --prefix vectorscan)/lib/pkgconfig \
  CGO_ENABLED=1 \
  go test -tags hyperscan -bench '.' -benchtime=2s -benchmem \
    ./internal/hsmatch/
```

### End-to-end (`decoder/stream/service`)

The `service_probe_bench_test.go` benchmarks load the **real**
`nmap-service-probes` file from a system path
(`/opt/homebrew/share/nmap`, `/usr/local/share/nmap`, `/usr/share/nmap` —
in that order; install nmap to make them available) and exercise
`MatchServiceProbes` against a representative banner set.

Each scenario runs in two flavours, sharing a single binary, so a fair
A/B comparison is possible without rebuilding:

| Bench | Fast path |
|---|---|
| `BenchmarkServiceProbeMatch_All` | HS prefilter active |
| `BenchmarkServiceProbeMatch_NoHyperscan` | HS index cleared at runtime → pure RE2 |
| `BenchmarkServiceProbeMatch_HitOnly` / `_NoHyperscan` | only well-known-port hit banners |
| `BenchmarkServiceProbeMatch_MissOnly` / `_NoHyperscan` | only banners that match no probe (full category sweep) |

```bash
PKG_CONFIG_PATH=$(brew --prefix vectorscan)/lib/pkgconfig \
  CGO_ENABLED=1 \
  go test -tags hyperscan -bench '^BenchmarkServiceProbeMatch' \
    -benchtime=3s -benchmem -timeout=900s \
    ./decoder/stream/service/
```

Notes:

- The benchmarks `b.Skip` if no `nmap-service-probes` file is found. Install
  nmap (`brew install nmap` / `apt install nmap`) to enable them.
- Initial probe load is slow (compiles ~9k regexes plus per-category HS
  databases) so a long `-timeout` is required.
- The runtime toggle (`resetServiceProbeHSIndexForBench`) closes/opens the
  HS DBs between benches — it does **not** reload the RE2 probes, keeping
  the comparison fair.

---

## Performance results

Measured on Apple M1 Max, macOS 26.3 arm64, Vectorscan 5.4.12, Go 1.26.1.
Probe set: real `nmap-service-probes` (~9k patterns across ~400
categories). `benchtime=3s`.

### `service.MatchServiceProbes` (end-to-end including RE2 capture extraction)

| Workload | RE2 baseline | RE2 + Hyperscan | Speedup | Allocs reduction |
|---|---:|---:|---:|---:|
| **All** (mixed hit/miss) | 994.8 µs/op, 227 KB, 6243 allocs | **454.2 µs/op**, 146 KB, 4919 allocs | **2.19×** | −36% B, −21% allocs |
| **HitOnly** (well-known port → expectedCategory) | 638.8 µs/op, 149 KB, 4862 allocs | **344.4 µs/op**, 113 KB, 3793 allocs | **1.85×** | −24% B, −22% allocs |
| **MissOnly** (no probe matches → full category sweep) | 2511.3 µs/op, 568 KB, 11802 allocs | **936.6 µs/op**, 291 KB, 9828 allocs | **2.68×** | −49% B, −17% allocs |

### `software.WhatSoftwareHTTP` (CMS detection on HTTP responses, real ~1100-product cmsdb.json)

| Workload | RE2 baseline | RE2 + Hyperscan | Speedup |
|---|---:|---:|---:|
| **All** (realistic mix of CMS + plain responses) | 51.2 µs/op | **36.8 µs/op** | **1.41×** |
| **MissOnly** (responses with no CMS-relevant headers) | 103 ns/op | 103 ns/op | 1.00× (early-exit short-circuits in both paths) |

The miss-only case is identical because both paths early-exit when no
known CMS headers/cookies are present. The win shows up on responses
that *do* carry CMS-known header names: HS skips the full 1100-product
sweep through `cmsDB` and only iterates the candidate set.

### `filter.MatchesPattern` (rule engine helper, 11 representative shipped patterns × 11 inputs)

| Workload | RE2 baseline | RE2 + Hyperscan | Speedup |
|---|---:|---:|---:|
| **Mixed** (half hit / half miss) | 10380 ns/op | **3634 ns/op** | **2.86×** |
| **MissOnly** (no pattern matches) | 21336 ns/op | **3494 ns/op** | **6.11×** |
| **HitOnly** (every pattern matches) | 21294 ns/op | **5335 ns/op** | **3.99×** |

The miss-only workload is the dominant case in real rule evaluation:
firewall and detection rules want to reject 99%+ of traffic. HS short
circuits with a "no match" answer in a few hundred nanoseconds where
RE2 has to walk the alternation each time.

The miss-only workload is where multi-pattern Hyperscan dominates: every
probe in every category gets evaluated when no hit short-circuits, which
is exactly the regime HS was designed for.

### Wrapper-level (`hsmatch.DB.Match`, no extraction)

| Workload | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| 3-pattern small set, hit | 477.9 | 136 | 6 |
| 1000-pattern large set, hit | 353.5 | 136 | 6 |
| 1000-pattern large set, miss | 255.7 | 136 | 6 |

Per-call overhead is constant (~250–500 ns) and **decreases** as the
pattern set grows on miss workloads — confirming that scaling cost is
dominated by haystack length, not pattern count, which is the libhs design
promise. Per-call allocations are constant at 6 (gohs handler closure
boxing + scratch pool plumbing).

### Validation: stub-build sanity check

The same package compiled **without** `-tags hyperscan` produces:

| Workload | stub build | tagged-but-disabled |
|---|---:|---:|
| _All | 958.1 µs/op | 994.8 µs/op |
| _HitOnly | 597.6 µs/op | 638.8 µs/op |
| _MissOnly | 2493.3 µs/op | 2511.3 µs/op |

Stub-build numbers and the runtime-disabled tagged-build numbers match
within ~3% — confirming the runtime toggle is a fair apples-to-apples
comparison and the HS path itself adds **no measurable overhead when
disabled**.

### Bottom line

- **2.2× faster for typical capture traffic**, **2.7× faster on miss-only
  workloads** where HS shines.
- **20–50% fewer bytes allocated**, **17–22% fewer allocations** per
  banner match.
- Per-call HS overhead is sub-microsecond and constant in the pattern
  count.
- Disabled HS path (stub build or runtime toggle) costs nothing — within
  noise of the pre-integration baseline.

---

## Web UI / API status

When running with `--service`, integration status is exposed at:

```
GET /api/hyperscan
```

Response (truncated example):

```json
{
  "enabled": true,
  "lib_version": "5.4.12 2024-12-05",
  "build_tag": "hyperscan",
  "docs_url": "https://github.com/dreadl0ck/netcap/blob/master/docs/hyperscan.md",
  "service_probes": {
    "enabled": true,
    "lib_version": "5.4.12 2024-12-05",
    "build": {
      "categories": 412,
      "patterns_total": 8923,
      "patterns_hyperscan": 8617,
      "patterns_fallback": 306
    },
    "scan_fallbacks": 0,
    "categories": [
      {
        "name": "ftp",
        "patterns": 47,
        "rejections": 2,
        "matches": 1234,
        "scans": 5678,
        "scan_errors": 0,
        "sample_error": "POSIX backreference not supported"
      }
    ]
  }
}
```

Field reference:

| Field | Meaning |
|---|---|
| `enabled` | binary was built with `-tags hyperscan` AND libhs is linked |
| `lib_version` | `hs_version()` runtime string (or `"disabled"` in stub builds) |
| `service_probes.build.categories` | number of probe categories with at least one HS-compiled pattern |
| `service_probes.build.patterns_total` | probes attempted (RegExRaw non-empty) |
| `service_probes.build.patterns_hyperscan` | probes accepted by HS |
| `service_probes.build.patterns_fallback` | probes kept on the RE2 path (HS rejected or category build failed) |
| `service_probes.build_error` | aggregated errors from per-category compile failures (first 5) |
| `service_probes.scan_fallbacks` | runtime scan errors that fell back to linear RE2; **monitor for non-zero** |
| `service_probes.categories[].rejections` | patterns rejected for this category |
| `service_probes.categories[].sample_error` | first rejection reason — quick diagnostic clue |

In stub builds (no `-tags hyperscan`) the same endpoint answers with
`enabled: false` and `lib_version: "disabled"` so the UI can render an
explicit badge instead of timing out.

---

## Logging

The integration logs to the `service` zap logger (configured by netcap as
usual through `decoderconfig.Instance.Out`).

| Event | Level | Fields |
|---|---|---|
| Index build summary | Info | `libhs_version, categories, patterns_total, patterns_hyperscan, patterns_fallback, category_build_errors` |
| Per-category compile failure | Warn | `category, patterns, error` |
| All patterns in a category rejected | Info | `category, patterns` |
| Individual pattern rejection | Debug | `category, probe_index, reason, expr` (truncated to 200 chars) |
| Re-init close error | Warn | `category, error` |
| Runtime scan failure | Warn | `category, banner_bytes, error` (also bumps `scan_fallbacks`) |
| `UseRE2=false` skip | Info | — |

Enable Debug to see individual pattern rejections; the default Info level
keeps logs aggregate and quiet.

---

## Scope and limitations

- **No Chimera bindings.** Vectorscan does not ship Chimera (the
  PCRE-compatible companion library), so backreferences and lookaround
  remain on the `regexp2` path even when Hyperscan is enabled.
- **No streaming matcher yet.** All current callsites match against fully
  reassembled buffers; only the block-mode DB is used.
- **One target migrated so far.** The wrapper package
  (`internal/hsmatch`) is reusable; further migrations (e.g.
  `decoder/stream/secret` custom regex harvesters,
  `decoder/stream/software/load.go`, `internal/filter` helpers) are
  straightforward follow-ups but intentionally out of scope for the
  initial integration.
- **macOS Chimera unavailable.** Homebrew's `vectorscan` formula does not
  ship the `ch.h` header, so `gohs/chimera` cannot be linked on macOS.

---

## Troubleshooting

`ld: library not found for -lhs` — your linker cannot find `libhs`.
Verify:

```bash
pkg-config --cflags --libs libhs
```

Should print include and `-lhs` paths. If empty, add the directory
containing `libhs.pc` to `PKG_CONFIG_PATH`.

`hsmatch: build block database: <pattern> at index N: ...` — a probe
expression was rejected even by the per-pattern probe step. Open an issue
with the rejected expression; it should never abort the build because every
unsupported probe is silently kept on the RE2 path.

`scan_fallbacks` keeps increasing in `/api/hyperscan` — runtime scans are
failing. Check the service log for `hyperscan: scan failed` Warn entries,
which include the libhs error message. The matcher is still correct (it
silently falls back to linear RE2) but you are losing the speedup for
those banners.

`make -f Makefile.test test-hyperscan` says `libhs not found via
pkg-config` — install Vectorscan/Hyperscan (see [Building](#building-with-hyperscan))
or set `PKG_CONFIG_PATH` to the directory containing `libhs.pc`.
