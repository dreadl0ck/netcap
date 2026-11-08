#!/bin/sh
# PREFIX must name a dedicated installation; never overwrite Homebrew libraries.
set -eu
. "$(dirname "$0")/yara-x.env"
: "${PREFIX:?set PREFIX to the YARA-X installation directory}"
case "$PREFIX" in /*) ;; *) echo 'PREFIX must be absolute' >&2; exit 1 ;; esac
case "${JOBS:-4}" in 1|2|3|4) ;; *) echo 'JOBS must be between 1 and 4' >&2; exit 1 ;; esac
test "$(rustc +"$YARA_X_RUST_VERSION" --version | cut -d ' ' -f 2)" = "$YARA_X_RUST_VERSION"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
url="https://codeload.github.com/VirusTotal/yara-x/tar.gz/refs/tags/v$YARA_X_VERSION"
if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 "$url" -o "$tmp/source.tar.gz"
else
    wget -O "$tmp/source.tar.gz" "$url"
fi
if command -v sha256sum >/dev/null 2>&1; then
    printf '%s  %s\n' "$YARA_X_SHA256" "$tmp/source.tar.gz" | sha256sum -c -
else
    printf '%s  %s\n' "$YARA_X_SHA256" "$tmp/source.tar.gz" | shasum -a 256 -c -
fi
tar -xzf "$tmp/source.tar.gz" -C "$tmp"
cd "$tmp/yara-x-$YARA_X_VERSION"
cargo +"$YARA_X_RUST_VERSION" build --locked --release -j "${JOBS:-4}" -p yara-x-capi
mkdir -p "$PREFIX/lib/pkgconfig" "$PREFIX/include"
case "$(uname -s)" in
    Darwin)
        library=libyara_x_capi.dylib
        cp "target/release/$library" "$PREFIX/lib/"
        install_name_tool -id "$PREFIX/lib/$library" "$PREFIX/lib/$library"
        ;;
    Linux) library=libyara_x_capi.so; cp "target/release/$library" "$PREFIX/lib/" ;;
    *) echo 'Unsupported YARA-X platform' >&2; exit 1 ;;
esac
cp target/release/libyara_x_capi.a "$PREFIX/lib/"
cp capi/include/yara_x.h "$PREFIX/include/"
# An absolute library avoids earlier -L/opt/homebrew/lib flags selecting an old ABI.
cat > "$PREFIX/lib/pkgconfig/yara_x_capi.pc" <<EOF
prefix=$PREFIX
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: yara_x_capi
Description: YARA-X C API
Version: $YARA_X_VERSION
Libs: \${libdir}/$library -Wl,-rpath,\${libdir}
Cflags: -I\${includedir}
EOF
PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" pkg-config --exact-version="$YARA_X_VERSION" yara_x_capi
