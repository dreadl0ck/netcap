# Base Alpine builder image for netcap musl builds with DPI support
# This image contains all build dependencies including nDPI and libprotoident
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
    extra-cmake-modules-doc \
    pkgconfig \
    json-c-dev \
    wget

# Install wandio (required by libtrace)
RUN cd /tmp && \
    wget https://github.com/wanduow/wandio/archive/4.2.3-1.tar.gz && \
    tar xfz 4.2.3-1.tar.gz && \
    cd wandio-4.2.3-1 && \
    ./bootstrap.sh && \
    ./configure && \
    make && \
    make install && \
    cd / && \
    rm -rf /tmp/4.2.3-1.tar.gz /tmp/wandio-4.2.3-1

# Install libtrace
RUN cd /tmp && \
    wget https://github.com/LibtraceTeam/libtrace/archive/4.0.17-1.tar.gz && \
    tar xfz 4.0.17-1.tar.gz && \
    cd libtrace-4.0.17-1 && \
    ./bootstrap.sh && \
    ./configure && \
    make && \
    make install && \
    cd / && \
    rm -rf /tmp/4.0.17-1.tar.gz /tmp/libtrace-4.0.17-1

# Install libflowmanager (required by libprotoident)
RUN cd /tmp && \
    wget https://github.com/wanduow/libflowmanager/archive/3.0.0.tar.gz && \
    tar xfz 3.0.0.tar.gz && \
    cd libflowmanager-3.0.0 && \
    ./bootstrap.sh && \
    ./configure && \
    make && \
    make install && \
    cd / && \
    rm -rf /tmp/3.0.0.tar.gz /tmp/libflowmanager-3.0.0

# Install libprotoident
RUN cd /tmp && \
    wget https://github.com/wanduow/libprotoident/archive/2.0.15-1.tar.gz && \
    tar xfz 2.0.15-1.tar.gz && \
    cd libprotoident-2.0.15-1 && \
    ./bootstrap.sh && \
    ./configure && \
    make && \
    make install && \
    cd / && \
    rm -rf /tmp/2.0.15-1.tar.gz /tmp/libprotoident-2.0.15-1

# Install nDPI
RUN cd /tmp && \
    wget https://github.com/ntop/nDPI/archive/4.14.tar.gz && \
    tar xfz 4.14.tar.gz && \
    cd nDPI-4.14 && \
    ./autogen.sh && \
    ./configure && \
    make && \
    make install && \
    cd / && \
    rm -rf /tmp/4.14.tar.gz /tmp/nDPI-4.14

# Set CGO flags for DPI libraries
ENV CFLAGS="-I/usr/local/lib"
ENV CPPFLAGS="-I/usr/local/lib"
ENV CXXFLAGS="-I/usr/local/lib"
ENV LDFLAGS="--verbose -v -L/usr/local/lib -llinear -ltrace -lndpi -lpcap -lm -pthread"
ENV LD_LIBRARY_PATH="/usr/local/lib:/usr/lib:/go"
ENV LD_RUN_PATH="/usr/local/lib"

# Configure linker
RUN ldconfig /usr/local/lib/* 2>/dev/null || true && \
    ldconfig /go/* 2>/dev/null || true

# Install the Rust toolchain for yara-x.
#
# The previous `curl https://sh.rustup.rs | sh -s -- -y` never ran at all: curl
# is not in the package list above and is not in the golang alpine base either.
# A pipeline reports the exit status of its LAST command, so
# `curl-that-does-not-exist | sh` exits 0 — sh reads empty stdin and returns
# success. The step looked fine in every build log and installed nothing.
#
# Downloaded with wget to a file and executed directly, so there is no pipeline
# whose exit status can hide a missing downloader.
#
# Not apk's rust: Alpine ships 1.87, and yara-x 1.14 pulls in cranelift/wasmtime
# which require 1.89. rustup tracks stable and is the only option here.
RUN wget -O /tmp/rustup-init.sh https://sh.rustup.rs && \
    chmod +x /tmp/rustup-init.sh && \
    /tmp/rustup-init.sh -y --profile minimal --default-toolchain stable && \
    rm /tmp/rustup-init.sh
ENV PATH="/root/.cargo/bin:${PATH}"

# Assert the toolchain exists before anything depends on it.
RUN rustc --version && cargo --version

# Tell cargo to link with gcc.
#
# rustup's x86_64-unknown-linux-musl target defaults to a `musl-gcc` wrapper,
# which Alpine does not ship and does not need: its gcc is already musl-native
# (gcc -dumpmachine reports x86_64-alpine-linux-musl). Without this every crate
# with a build script fails at "linker `musl-gcc` not found".
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=gcc

# Build and install yara-x v1.14.0 C API library.
#
# NOTE the absence of `|| true`. The previous version ended with
# `... && cp yara_x.h && ldconfig || true && cd / && rm -rf ...`, and `||` binds
# to the whole preceding && chain — so a failure anywhere in it, including the
# cargo build and the header copy, was swallowed. Combined with the rustup bug
# above that is why the published builder image has never contained yara-x, and
# why every netcap service build has failed at `pkg-config -- yara_x_capi` or,
# once the .pc file existed, at a missing yara_x.h.
#
# ldconfig is allowed to fail on its own line only, which is what was intended.
#
# RUSTFLAGS="-C target-feature=-crt-static" is required, not incidental. On the
# musl target rustup's std defaults to static linking, but proc-macro crates
# (thiserror-impl, serde_derive, …) must be built as shared objects, and the
# static objects are not position-independent — so linking them fails with
# "relocation R_X86_64_32 ... can not be used when making a shared object".
# Disabling crt-static makes std dynamic and lets the proc-macros link.
#
# The resulting libyara_x_capi.so is then dynamically linked against musl, which
# is what the runtime stage expects: docker/service/Dockerfile copies
# /usr/local/lib/* into an Alpine image and runs ldconfig over it.
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
    rm -rf /tmp/v1.14.0.tar.gz /tmp/yara-x-1.14.0
RUN ldconfig /usr/local/lib 2>/dev/null || true

# Fail the build here rather than in every downstream netcap build.
#
# The two bugs above were invisible for as long as they existed because nothing
# asserted the outcome. These four checks are cheap and turn a silent gap into a
# build error at the place that caused it.
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

# Protocol buffer compiler and the gogofaster plugin.
#
# types/netcap.pb.go is generated from netcap.proto and is gitignored, so a
# clean checkout has no types package at all -- every build fails with
# "undefined: Alert", "undefined: PacketContext" and so on. Carrying protoc here
# lets both CI and the service image regenerate it rather than depending on a
# copy that happens to exist on a developer's disk, which is the same class of
# problem that frontend/dist caused.
#
# The plugin version is pinned to the gogo/protobuf release in go.mod (v1.3.2)
# so the generated code matches the runtime it is compiled against.
# The final check is `command -v`, not `test -x` against a guessed path: the
# invariant protoc actually needs is that the plugin is resolvable on PATH, and
# GOPATH here is /go (set by the golang base image), not ~/go. Note there is no
# `|| (echo ... && exit 1)` tail -- as the yara-x notes above record, `||` binds
# to the whole && chain and replaces the real error with a generic message,
# which is exactly what hid this mistake on the first attempt.
RUN apk add --no-cache protobuf protobuf-dev && \
    go install github.com/gogo/protobuf/protoc-gen-gogofaster@v1.3.2 && \
    protoc --version && \
    command -v protoc-gen-gogofaster

# Set working directory
WORKDIR /workspace

# Verify Go installation
RUN go version

# Verify libraries are installed
RUN ldconfig -p 2>/dev/null || true

# This image is ready to accept source code and build with DPI support
CMD ["/bin/sh"]

