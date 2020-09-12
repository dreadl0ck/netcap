#!/bin/bash

# musl
NODPI=false VERSION=${VERSION} zeus/scripts/build-alpine-docker.sh

# glibc
NODPI=false VERSION=${VERSION} zeus/scripts/build-ubuntu-docker.sh