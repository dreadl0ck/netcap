#!/usr/bin/env bash
set -euo pipefail

out=${1:?usage: bash zeus/scripts/benchmark-c-dpi.sh EXISTING_OUTPUT_DIRECTORY}
[[ -d "$out" && -f go.mod ]] || { printf 'Run from the netcap module with an existing output directory\n' >&2; exit 2; }
out=$(realpath "$out")
count=${COUNT:-6}
benchtime=${BENCHTIME:-1000x}
native_benchtime=${NATIVE_BENCHTIME:-2000x}
hot_benchtime=${HOT_BENCHTIME:-20000x}
godpi=$(go list -m -f '{{.Dir}}' github.com/dreadl0ck/go-dpi)
corpus=${DPI_CORPUS:-$godpi/godpi_example/dumps}
benchstat=golang.org/x/perf/cmd/benchstat@v0.0.0-20260929162123-406019bb8b68

{
    go version
    go env GOOS GOARCH GOMAXPROCS GOWORK
    git rev-parse HEAD
    go list -m -f '{{.Path}} {{.Version}} {{.Dir}}' github.com/dreadl0ck/go-dpi
    if [[ -e "$godpi/.git" ]]; then git -C "$godpi" rev-parse HEAD; fi
    pkg-config --modversion libndpi || true
} > "$out/c-dpi-environment.txt"

DPI_CORPUS="$corpus" go test -race -short ./internal/dpi -count=1 -v > "$out/c-dpi-correctness.txt" 2>&1

for mode in legacy-safe budget incremental; do
    case "$mode" in legacy-safe) legacy=1 ;; budget) legacy=budget ;; incremental) legacy= ;; esac
    DPI_BENCH_LEGACY="$legacy" go test ./internal/dpi -run '^$' -bench '^BenchmarkCIntegration$' \
        -benchtime="$benchtime" -count="$count" -benchmem > "$out/c-dpi-$mode.txt"
done
go run "$benchstat" "$out/c-dpi-legacy-safe.txt" "$out/c-dpi-budget.txt" "$out/c-dpi-incremental.txt" > "$out/c-dpi-benchstat.txt"

for mode in legacy-safe incremental; do
    legacy=; [[ "$mode" != legacy-safe ]] || legacy=1
    DPI_BENCH_LEGACY="$legacy" go test github.com/dreadl0ck/go-dpi/modules/wrappers -run '^$' -bench '^BenchmarkNativeIntegration$' \
        -benchtime="$native_benchtime" -count="$count" -cpu=1,2,4,8 -benchmem > "$out/c-dpi-native-$mode.txt"
    DPI_BENCH_LEGACY="$legacy" go test ./internal/dpi -run '^$' -bench '^BenchmarkCIntegrationHotParallel$' \
        -benchtime="$hot_benchtime" -count="$count" -cpu=1,2,4,8 -benchmem > "$out/c-dpi-hot-$mode.txt"
done
go run "$benchstat" "$out/c-dpi-native-legacy-safe.txt" "$out/c-dpi-native-incremental.txt" > "$out/c-dpi-native-benchstat.txt"
go run "$benchstat" "$out/c-dpi-hot-legacy-safe.txt" "$out/c-dpi-hot-incremental.txt" > "$out/c-dpi-hot-benchstat.txt"

go test -c -o "$out/c-dpi.test" ./internal/dpi
if [[ $(uname) == Darwin ]]; then time_args=(-l); else time_args=(-v); fi
for shape in churn short; do
    cardinality=; [[ "$shape" != short ]] || cardinality=32768
    for mode in legacy-safe incremental-1 incremental-8; do
        legacy=; workers=1
        [[ "$mode" != legacy-safe ]] || legacy=1
        [[ "$mode" != incremental-8 ]] || workers=8
        DPI_MEMORY_PROBE=1 DPI_MEMORY_CARDINALITY="$cardinality" DPI_BENCH_LEGACY="$legacy" DPI_BENCH_WORKERS="$workers" \
            /usr/bin/time "${time_args[@]}" "$out/c-dpi.test" -test.run '^TestCIntegrationMemory$' \
            > "$out/c-dpi-memory-$shape-$mode.txt" 2>&1
    done
done
python3 zeus/scripts/summarize-c-dpi.py "$out"
