#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
revision=3709d1c6905d9527885c62f66f49a955c7b0d191
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
git clone --quiet https://github.com/alphasoc/flightsim.git "$temporary/source"
git -C "$temporary/source" checkout --quiet "$revision"
test "$(git -C "$temporary/source" rev-parse HEAD)" = "$revision"
architecture=$(docker info --format '{{.Architecture}}')
case "$architecture" in aarch64|arm64) architecture=arm64 ;; x86_64|amd64) architecture=amd64 ;; *) exit 2 ;; esac
cd "$temporary/source/v2"
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go build -mod=vendor -o "$root/flightsim" .
printf 'Built FlightSim %s for linux/%s\n' "$revision" "$architecture"
