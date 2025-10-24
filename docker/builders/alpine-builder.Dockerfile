# Base Alpine builder image for netcap musl builds
# This image contains all build dependencies and can be reused across builds
FROM --platform=linux/amd64 golang:1.25.1-alpine

# Install all build dependencies
RUN apk update && \
    apk add --no-cache \
    gcc \
    libpcap-dev \
    libnetfilter_queue-dev \
    linux-headers \
    musl-utils \
    musl-dev \
    git \
    vim \
    autoconf \
    automake \
    libtool \
    make \
    g++ \
    bison \
    flex \
    cmake \
    build-base \
    abuild \
    binutils \
    binutils-doc \
    gcc-doc \
    cmake-doc \
    extra-cmake-modules \
    extra-cmake-modules-doc

# Set working directory
WORKDIR /workspace

# Verify Go installation
RUN go version

# This image is ready to accept source code and build
CMD ["/bin/sh"]

