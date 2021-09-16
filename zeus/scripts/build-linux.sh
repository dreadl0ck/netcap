#!/bin/bash

# musl
NODPI=false ARGS="--no-cache" VERSION=v${VERSION} zeus/scripts/build-alpine-docker.sh

# glibc
NODPI=false ARGS="--no-cache" VERSION=v${VERSION} zeus/scripts/build-ubuntu-docker.sh