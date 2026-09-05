# Base Alpine builder image for netcap musl builds
# This image contains all build dependencies and can be reused across builds
ARG TARGETPLATFORM=linux/amd64
FROM --platform=$TARGETPLATFORM golang:1.27.0-alpine

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

# pkg-config, needed to consume the yara-x .pc file written below. It was
# missing from the package list, so the file this image installs could not
# actually be read by anything.
RUN apk add --no-cache pkgconfig

# Install the Rust toolchain for yara-x.
#
# The previous `curl https://sh.rustup.rs | sh -s -- -y` never ran: curl is not
# in the package list above and is not in the golang alpine base. A pipeline
# reports the exit status of its LAST command, so
# `curl-that-does-not-exist | sh` exits 0 — sh reads empty stdin and succeeds.
# The step looked fine in every build log and installed nothing, which is why
# this image has never contained yara-x.
#
# Downloaded to a file and executed directly, so no pipeline can hide a missing
# downloader. Not apk's rust: Alpine ships 1.87 and yara-x 1.14 pulls in
# cranelift/wasmtime, which require 1.89.
RUN wget -O /tmp/rustup-init.sh https://sh.rustup.rs && \
    chmod +x /tmp/rustup-init.sh && \
    /tmp/rustup-init.sh -y --profile minimal --default-toolchain stable && \
    rm /tmp/rustup-init.sh
ENV PATH="/root/.cargo/bin:${PATH}"

RUN rustc --version && cargo --version

# Alpine ships no musl-gcc and needs none — its gcc already targets musl
# (x86_64-alpine-linux-musl). rustup's musl target defaults to that wrapper, so
# without this every crate with a build script fails at "linker `musl-gcc` not
# found".
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=gcc

# Build and install yara-x v1.14.0 C API library.
#
# No `|| true` here. The previous version ended
# `... && cp yara_x.h && ldconfig || true && cd / && rm -rf ...`, and `||` binds
# to the entire preceding && chain — so the guard intended for ldconfig also
# swallowed a failed cargo build and a failed header copy.
#
# RUSTFLAGS="-C target-feature=-crt-static" is required: on musl, rustup's std
# is static and not position-independent, but proc-macro crates must be shared
# objects, so they fail with "relocation R_X86_64_32 ... can not be used when
# making a shared object".
RUN cd /tmp && \
    wget https://github.com/VirusTotal/yara-x/archive/refs/tags/v1.14.0.tar.gz && \
    tar xfz v1.14.0.tar.gz && \
    cd yara-x-1.14.0 && \
    RUSTFLAGS="-C target-feature=-crt-static" cargo build --release -p yara-x-capi && \
    cp target/release/libyara_x_capi.so /usr/local/lib/ && \
    cp target/release/libyara_x_capi.a /usr/local/lib/ && \
    mkdir -p /usr/local/include && \
    cp capi/include/yara_x.h /usr/local/include/ && \
    cd / && \
    rm -rf /tmp/v1.14.0.tar.gz /tmp/yara-x-1.14.0 /root/.cargo/registry
RUN ldconfig /usr/local/lib 2>/dev/null || true

# Fail here rather than in every downstream netcap build. The bugs above were
# invisible for as long as they existed because nothing asserted the outcome.
RUN test -f /usr/local/include/yara_x.h || (echo "yara_x.h missing" && exit 1) && \
    test -f /usr/local/lib/libyara_x_capi.so || (echo "libyara_x_capi.so missing" && exit 1) && \
    test -f /usr/local/lib/libyara_x_capi.a || (echo "libyara_x_capi.a missing" && exit 1)

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

