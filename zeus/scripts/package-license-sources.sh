#!/bin/sh

set -eu

export LC_ALL=C

version="${VERSION:?VERSION must identify the release}"
output="dist-license-sources"
bundle="$output/netcap-third-party-source-v${version}"

rm -rf "$output"
mkdir -p "$bundle"

fetch() {
    url="$1"
    name="$2"
    checksum="$3"
    curl --fail --location --retry 3 "$url" --output "$bundle/$name"
    printf '%s  %s\n' "$checksum" "$bundle/$name" | shasum -a 256 -c -
}

fetch "https://github.com/ntop/nDPI/archive/refs/tags/4.14.tar.gz" "nDPI-4.14.tar.gz" "954135ee14ad6bd74a78a10db560b534b8f2083ad0615f5c1a2c376fff0301e0"
fetch "https://github.com/LibtraceTeam/libprotoident/archive/refs/tags/2.0.15-1.tar.gz" "libprotoident-2.0.15-1.tar.gz" "cfa7c2d8db8e701db9f991e4f58fd9a284db65e866194ad54e413202163b7289"
fetch "https://github.com/LibtraceTeam/libprotoident/archive/refs/tags/2.0.15-2.tar.gz" "libprotoident-2.0.15-2.tar.gz" "2b43a492fe1d7ada2e7b7b164c8e35220b35bf816bd971c7f77decc74b69801e"
fetch "https://github.com/LibtraceTeam/libtrace/archive/refs/tags/4.0.17-1.tar.gz" "libtrace-4.0.17-1.tar.gz" "e3238661e5bf9133dd9f864c6d2f7a40c91ef07eada6d60f6defccea1d4536bd"
fetch "https://github.com/LibtraceTeam/libtrace/archive/refs/tags/4.0.34-1.tar.gz" "libtrace-4.0.34-1.tar.gz" "b3e73b9ca6757094047295937ab4d834155a0c64674f499132b56e8f81f8fcc9"
fetch "https://github.com/LibtraceTeam/libflowmanager/archive/refs/tags/3.0.0.tar.gz" "libflowmanager-3.0.0.tar.gz" "c0eb2a25eedecad150a15e25650750078cb525c35aec3add2214a1a9a7fae0a9"
fetch "https://github.com/LibtraceTeam/libflowmanager/archive/refs/tags/3.0.0-3.tar.gz" "libflowmanager-3.0.0-3.tar.gz" "f83454196196426cd96c6bbbd61be327dc07e02aa9edaf074024fdc86fddda66"
fetch "https://github.com/LibtraceTeam/wandio/archive/refs/tags/4.2.3-1.tar.gz" "wandio-4.2.3-1.tar.gz" "0b7499dd73fd167dfb35abe80b25b36fe757e51f7cbd8bf5810d24951ca41735"
fetch "https://github.com/LibtraceTeam/wandio/archive/refs/tags/4.2.7-1.tar.gz" "wandio-4.2.7-1.tar.gz" "45021795b5c4d1609ba509358e730ea605c4c9621704d75214abb003f37602ab"
fetch "https://github.com/google/magika/archive/refs/tags/cli/v1.0.2.tar.gz" "magika-cli-1.0.2.tar.gz" "bae42b31c8f419f34043cc2cf26fa42d2ade7f7c91e2fb54919914432f799699"
fetch "https://github.com/VirusTotal/yara-x/archive/refs/tags/v1.14.0.tar.gz" "yara-x-1.14.0.tar.gz" "3a251473fc75673196b0acd678893f90478b83a6dd5ce255f53e2ac086a50254"
fetch "https://crates.io/api/v1/crates/colored/3.0.0/download" "colored-3.0.0.crate" "fde0e0ec90c9dfb3b4b1a0891a7dcd0e2bffde2f7efed5fe7c9bb00e5bfb915e"

cp LICENSE "$bundle/GPL-3.0.txt"
cp legal/licenses/LGPL-3.0.txt "$bundle/LGPL-3.0.txt"
cp legal/licenses/JA4-BSD-3-Clause.txt "$bundle/JA4-BSD-3-Clause.txt"
cp legal/THIRD_PARTY_LICENSES.txt "$bundle/"
cp legal/THIRD_PARTY_RUST_LICENSES.txt "$bundle/"
cp legal/THIRD_PARTY_NOTICES.txt "$bundle/"

touch -t 198001010000 "$bundle" "$bundle"/*
COPYFILE_DISABLE=1 tar -cf - --uid 0 --gid 0 --numeric-owner -C "$output" "netcap-third-party-source-v${version}" | gzip -n > "$output/netcap-third-party-source-v${version}.tar.gz"
rm -rf "$bundle"
