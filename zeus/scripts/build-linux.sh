#!/bin/bash

set -e

if [[ -n "${NETCAP_RELEASE_IMAGES:-}" ]]; then
    exec python3 zeus/scripts/package-prebuilt-linux.py "${VERSION}" dpi
fi

# musl
NODPI=false VERSION=v${VERSION} zeus/scripts/build-alpine-docker.sh

# glibc
NODPI=false VERSION=v${VERSION} zeus/scripts/build-ubuntu-docker.sh
