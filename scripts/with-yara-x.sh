#!/bin/sh
# Usage: YARA_X_PREFIX=/absolute/prefix sh scripts/with-yara-x.sh go test ...
set -eu
. "$(dirname "$0")/yara-x.env"
: "${YARA_X_PREFIX:?set the installation from scripts/build-yara-x.sh}"
test -s "$YARA_X_PREFIX/lib/pkgconfig/yara_x_capi.pc"
export PKG_CONFIG_PATH="$YARA_X_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
pkg-config --exact-version="$YARA_X_VERSION" yara_x_capi
# Go's CGO cache does not key on PKG_CONFIG_PATH. Key it on the actual library.
case "$(uname -s)" in
    Darwin) library="$YARA_X_PREFIX/lib/libyara_x_capi.dylib" ;;
    Linux) library="$YARA_X_PREFIX/lib/libyara_x_capi.so" ;;
    *) echo 'Unsupported YARA-X platform' >&2; exit 1 ;;
esac
if command -v sha256sum >/dev/null 2>&1; then
    checksum=$(sha256sum "$library")
else
    checksum=$(shasum -a 256 "$library")
fi
checksum=${checksum%% *}
export CGO_CPPFLAGS="${CGO_CPPFLAGS:-} -DNETCAP_YARA_X_${checksum}=1"
export GOWORK=off GOMAXPROCS=4
export GOFLAGS="${GOFLAGS:-} -p=4"
exec "$@"
