#!/bin/bash
set -euo pipefail

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
state=/usr/local/share/netcap/dpi
sudo mkdir -p "$state"
abi=$(printf '%s\n' "$(dpkg --print-architecture)" "$(getconf GNU_LIBC_VERSION)" "${CC:-cc}" "${CFLAGS:-}" "${CXXFLAGS:-}" "${CPPFLAGS:-}" "${LDFLAGS:-}" | sha256sum | cut -c1-16)

install_lib() (
    repo=$1 version=$2 digest=$3 bootstrap=$4
    name=${repo##*/}
    shift 4
    receipt="$state/$name-$version-$abi.sha256"
    if [[ -s $receipt ]] && sha256sum --status -c "$receipt"; then
        printf 'Reusing %s %s\n' "$name" "$version"
        exit 0
    fi
    curl -fsSL "https://codeload.github.com/$repo/tar.gz/refs/tags/$version" -o source.tgz
    printf '%s  source.tgz\n' "$digest" | sha256sum -c -
    tar xzf source.tgz
    cd "$name-$version"
    "./$bootstrap"
    ./configure
    make
    sudo make install
    sudo ldconfig
    sha256sum "$@" > "$work/receipt"
    sudo install -m644 "$work/receipt" "$receipt"
)

inc=/usr/local/include
lib=/usr/local/lib
install_lib LibtraceTeam/wandio 4.2.3-1 0b7499dd73fd167dfb35abe80b25b36fe757e51f7cbd8bf5810d24951ca41735 bootstrap.sh "$inc/wandio.h" "$lib/libwandio.so"
install_lib LibtraceTeam/libtrace 4.0.17-1 e3238661e5bf9133dd9f864c6d2f7a40c91ef07eada6d60f6defccea1d4536bd bootstrap.sh "$inc/libtrace.h" "$lib/libtrace.so"
install_lib LibtraceTeam/libflowmanager 3.0.0 c0eb2a25eedecad150a15e25650750078cb525c35aec3add2214a1a9a7fae0a9 bootstrap.sh "$inc/libflowmanager.h" "$lib/libflowmanager.so"
install_lib LibtraceTeam/libprotoident 2.0.15-1 cfa7c2d8db8e701db9f991e4f58fd9a284db65e866194ad54e413202163b7289 bootstrap.sh "$inc/libprotoident.h" "$lib/libprotoident.so"
install_lib ntop/nDPI 4.14 954135ee14ad6bd74a78a10db560b534b8f2083ad0615f5c1a2c376fff0301e0 autogen.sh /usr/include/ndpi/ndpi_api.h /usr/lib/libndpi.so
