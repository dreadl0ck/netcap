#!/bin/bash

# musl
NODPI=true ARGS="--build-arg TAGS=-tags=nodpi" VERSION=${VERSION}-nodpi zeus/scripts/build-alpine-docker.sh

# glibc
NODPI=true ARGS="--build-arg TAGS=-tags=nodpi" VERSION=${VERSION}-nodpi zeus/scripts/build-ubuntu-docker.sh