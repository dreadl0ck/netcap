#!/bin/bash

set -e

# musl
NODPI=false VERSION=v${VERSION} zeus/scripts/build-alpine-docker.sh

# glibc
NODPI=false VERSION=v${VERSION} zeus/scripts/build-ubuntu-docker.sh
