#!/bin/sh

set -eu

frontend_dir="cmd/capture/webui/frontend"
pnpm --dir "$frontend_dir" install --frozen-lockfile

go run ./tools/licenses -check
zeus/scripts/rust-licenses.sh -check
