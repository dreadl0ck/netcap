# Base Alpine builder image for netcap musl builds
# This image contains all build dependencies and can be reused across builds
ARG TARGETPLATFORM=linux/amd64
FROM --platform=$TARGETPLATFORM golang:1.25.1-alpine

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

# Install Rust toolchain for yara-x
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Build and install yara-x v1.14.0 C API library
RUN cd /tmp && \
    wget https://github.com/VirusTotal/yara-x/archive/refs/tags/v1.14.0.tar.gz && \
    tar xfz v1.14.0.tar.gz && \
    cd yara-x-1.14.0 && \
    cargo build --release -p yara-x-capi && \
    cp target/release/libyara_x_capi.so /usr/local/lib/ && \
    cp target/release/libyara_x_capi.a /usr/local/lib/ && \
    mkdir -p /usr/local/include && \
    cp capi/include/yara_x.h /usr/local/include/ && \
    ldconfig /usr/local/lib 2>/dev/null || true && \
    cd / && rm -rf /tmp/v1.14.0.tar.gz /tmp/yara-x-1.14.0 /root/.cargo/registry

# Create pkg-config file for yara-x
RUN mkdir -p /usr/local/lib/pkgconfig && \
    echo 'prefix=/usr/local' > /usr/local/lib/pkgconfig/yara_x_capi.pc && \
    echo 'libdir=${prefix}/lib' >> /usr/local/lib/pkgconfig/yara_x_capi.pc && \
    echo 'includedir=${prefix}/include' >> /usr/local/lib/pkgconfig/yara_x_capi.pc && \
    echo '' >> /usr/local/lib/pkgconfig/yara_x_capi.pc && \
    echo 'Name: yara_x_capi' >> /usr/local/lib/pkgconfig/yara_x_capi.pc && \
    echo 'Description: YARA-X C API' >> /usr/local/lib/pkgconfig/yara_x_capi.pc && \
    echo 'Version: 1.14.0' >> /usr/local/lib/pkgconfig/yara_x_capi.pc && \
    echo 'Libs: -L${libdir} -lyara_x_capi' >> /usr/local/lib/pkgconfig/yara_x_capi.pc && \
    echo 'Cflags: -I${includedir}' >> /usr/local/lib/pkgconfig/yara_x_capi.pc

# Set working directory
WORKDIR /workspace

# Verify Go installation
RUN go version

# This image is ready to accept source code and build
CMD ["/bin/sh"]

