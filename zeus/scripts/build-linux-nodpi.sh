#!/bin/bash

# musl
NODPI=true ARGS="--build-arg TAGS=-tags=nodpi" VERSION=nodpi_${VERSION} zeus/scripts/build-alpine-docker.sh

# glibc
NODPI=true ARGS="--build-arg TAGS=-tags=nodpi" VERSION=nodpi_${VERSION} zeus/scripts/build-ubuntu-docker.sh