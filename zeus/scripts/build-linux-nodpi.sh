#!/bin/bash

# musl
NODPI=true ARGS="--no-cache --build-arg TAGS=-tags=nodpi" VERSION=nodpi-v${VERSION} zeus/scripts/build-alpine-docker.sh

# glibc
NODPI=true ARGS="--no-cache --build-arg TAGS=-tags=nodpi" VERSION=nodpi-v${VERSION} zeus/scripts/build-ubuntu-docker.sh