#!/bin/bash

set -e

if [[ -n "${NETCAP_RELEASE_IMAGES:-}" ]]; then
    exec python3 zeus/scripts/package-prebuilt-linux.py "${VERSION}" nodpi
fi

# musl
NODPI=true ARGS="--no-cache --build-arg TAGS=-tags=nodpi" VERSION=nodpi-v${VERSION} zeus/scripts/build-alpine-docker.sh

# glibc
NODPI=true ARGS="--no-cache --build-arg TAGS=-tags=nodpi" VERSION=nodpi-v${VERSION} zeus/scripts/build-ubuntu-docker.sh
