#!/bin/bash
#
# Create a local go.work so builds resolve github.com/dreadl0ck/go-dpi from a
# sibling checkout instead of the version pinned in go.mod.
#
# go.work is deliberately NOT committed. It is a per-developer overlay: with it
# present every build in this module silently uses whatever is in ../go-dpi,
# which is what you want while changing both together and emphatically not what
# you want when reproducing a release. go.mod pins the real dependency, and a
# clean checkout builds against that pin with no workspace at all.
#
# Usage:
#   zeus setup-workspace                       # uses ../go-dpi
#   GO_DPI_PATH=/path/to/go-dpi zeus setup-workspace
#
# Remove it again with:  rm go.work go.work.sum
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

GO_DPI_PATH="${GO_DPI_PATH:-../go-dpi}"

if [ ! -d "$GO_DPI_PATH" ]; then
    echo "[ERROR] go-dpi checkout not found at: $GO_DPI_PATH" >&2
    echo "[INFO]  clone it beside this repository:" >&2
    echo "          git clone https://github.com/dreadl0ck/go-dpi ../go-dpi" >&2
    echo "[INFO]  or point at an existing one:" >&2
    echo "          GO_DPI_PATH=/path/to/go-dpi zeus setup-workspace" >&2
    exit 1
fi

if [ ! -f "$GO_DPI_PATH/go.mod" ]; then
    echo "[ERROR] $GO_DPI_PATH has no go.mod, so it is not a Go module" >&2
    exit 1
fi

# The workspace go directive must be >= every member's, or `go build` refuses
# with "go.work requires go >= X". Take the highest of the two rather than
# hardcoding, so this keeps working when either module moves.
netcap_go=$(awk '/^go /{print $2; exit}' go.mod)
dpi_go=$(awk '/^go /{print $2; exit}' "$GO_DPI_PATH/go.mod")
work_go=$(printf '%s\n%s\n' "$netcap_go" "$dpi_go" | sort -V | tail -1)

if [ -f go.work ]; then
    echo "[INFO] go.work already exists, overwriting"
fi

cat > go.work <<EOF
go $work_go

use (
	.
	$GO_DPI_PATH
)
EOF

echo "[INFO] wrote go.work (go $work_go, netcap=$netcap_go go-dpi=$dpi_go)"

# go.work.sum is generated, not written by hand.
go work sync

echo "[OK]   workspace active: builds now resolve go-dpi from $GO_DPI_PATH"
echo "[INFO] verify with: go list -m all | grep go-dpi"
echo "[INFO] disable temporarily with GOWORK=off, remove with: rm go.work go.work.sum"
