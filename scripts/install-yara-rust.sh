#!/bin/sh
set -eu
. "$(dirname "$0")/yara-x.env"
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) target=x86_64-unknown-linux-musl; checksum=e6599a1c7be58a2d8eaca66a80e0dc006d87bbcf780a58b7343d6e14c1605cb2 ;;
    Linux-aarch64) target=aarch64-unknown-linux-musl; checksum=a97c8f56d7462908695348dd8c71ea6740c138ce303715793a690503a94fc9a9 ;;
    *) echo 'Install Rust 1.95.0 with rustup on this platform before building YARA-X.' >&2; exit 1 ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
wget -O "$tmp/rustup-init" "https://static.rust-lang.org/rustup/archive/1.28.2/$target/rustup-init"
printf '%s  %s\n' "$checksum" "$tmp/rustup-init" | sha256sum -c -
chmod +x "$tmp/rustup-init"
host=$target
if [ ! -f /etc/alpine-release ]; then host="${target%-musl}-gnu"; fi
"$tmp/rustup-init" -y --profile minimal --default-host "$host" --default-toolchain "$YARA_X_RUST_VERSION"
