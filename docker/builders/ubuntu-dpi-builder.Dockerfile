# Base Ubuntu builder image for netcap glibc builds with DPI support
# This image contains all build dependencies including nDPI and libprotoident
ARG TARGETPLATFORM=linux/amd64
FROM --platform=$TARGETPLATFORM ubuntu:26.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Clean and update package lists
RUN apt-get clean && \
    apt-get update && \
    apt-get install -y \
    software-properties-common \
    busybox-static \
    net-tools \
    wget \
    curl \
    apt-transport-https \
    lsb-release \
    autogen \
    autoconf \
    automake \
    build-essential \
    flex \
    bison \
    libtool \
    gcc \
    libpcap-dev \
    zlib1g-dev \
    linux-headers-generic \
    git \
    vim \
    pkg-config \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install Go, verified against the go.dev release checksum. Unlike the Alpine
# builders this cannot track patch releases automatically, because the checksum
# pins one archive: bump the version, checksum and the check below together.
RUN wget https://go.dev/dl/go1.27.1.linux-amd64.tar.gz && \
    echo '63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445  go1.27.1.linux-amd64.tar.gz' | sha256sum -c - && \
    busybox tar -C /usr/local -xzf go1.27.1.linux-amd64.tar.gz && \
    rm go1.27.1.linux-amd64.tar.gz

# Set Go environment
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Cloudsmith only publishes libprotoident packages for Ubuntu 20.04 and older.
ARG WANDIO_VERSION=4.2.7-1
ARG LIBTRACE_VERSION=4.0.34-1
ARG FLOWMANAGER_VERSION=3.0.0-3
ARG PROTOIDENT_VERSION=2.0.15-2

RUN cd /tmp && \
    wget -q "https://github.com/LibtraceTeam/wandio/archive/refs/tags/${WANDIO_VERSION}.tar.gz" -O wandio.tar.gz && \
    echo '45021795b5c4d1609ba509358e730ea605c4c9621704d75214abb003f37602ab  wandio.tar.gz' | sha256sum -c - && \
    busybox tar xfz wandio.tar.gz && \
    cd "wandio-${WANDIO_VERSION}" && \
    ./bootstrap.sh && \
    ./configure --with-zlib --without-bzip2 --without-lzo --without-lzma --without-zstd --without-qatzip --without-lz4 --without-http && \
    make -j"$(nproc)" && \
    make install && \
    ldconfig && \
    rm -rf /tmp/wandio*

RUN cd /tmp && \
    wget -q "https://github.com/LibtraceTeam/libtrace/archive/refs/tags/${LIBTRACE_VERSION}.tar.gz" -O libtrace.tar.gz && \
    echo 'b3e73b9ca6757094047295937ab4d834155a0c64674f499132b56e8f81f8fcc9  libtrace.tar.gz' | sha256sum -c - && \
    busybox tar xfz libtrace.tar.gz && \
    cd "libtrace-${LIBTRACE_VERSION}" && \
    ./bootstrap.sh && \
    ./configure --without-dpdk --without-xdp --without-dag --without-pfring --without-numa --without-ncurses --without-llvm && \
    make -j"$(nproc)" && \
    make install && \
    ldconfig && \
    rm -rf /tmp/libtrace*

RUN cd /tmp && \
    wget -q "https://github.com/LibtraceTeam/libflowmanager/archive/refs/tags/${FLOWMANAGER_VERSION}.tar.gz" -O libflowmanager.tar.gz && \
    echo 'f83454196196426cd96c6bbbd61be327dc07e02aa9edaf074024fdc86fddda66  libflowmanager.tar.gz' | sha256sum -c - && \
    busybox tar xfz libflowmanager.tar.gz && \
    cd "libflowmanager-${FLOWMANAGER_VERSION}" && \
    ./bootstrap.sh && \
    ./configure && \
    make -j"$(nproc)" && \
    make install && \
    ldconfig && \
    rm -rf /tmp/libflowmanager*

RUN cd /tmp && \
    wget -q "https://github.com/LibtraceTeam/libprotoident/archive/refs/tags/${PROTOIDENT_VERSION}.tar.gz" -O libprotoident.tar.gz && \
    echo '2b43a492fe1d7ada2e7b7b164c8e35220b35bf816bd971c7f77decc74b69801e  libprotoident.tar.gz' | sha256sum -c - && \
    busybox tar xfz libprotoident.tar.gz && \
    cd "libprotoident-${PROTOIDENT_VERSION}" && \
    ./bootstrap.sh && \
    ./configure --with-tools=no && \
    make -j"$(nproc)" && \
    make install && \
    ldconfig && \
    rm -rf /tmp/libprotoident*

# Install nDPI from source
RUN apt-get update && \
    apt-get install -y libjson-c-dev && \
    rm -rf /var/lib/apt/lists/* && \
    wget https://github.com/ntop/nDPI/archive/4.14.tar.gz && \
    busybox tar xfz 4.14.tar.gz && \
    cd nDPI-4.14 && \
    ./autogen.sh && \
    ./configure && \
    make && \
    make install && \
    ldconfig && \
    cd / && \
    rm -rf /nDPI-4.14 /4.14.tar.gz

# Set CGO flags for DPI libraries
ENV CFLAGS="-I/usr/local/include/"
ENV LDFLAGS="-ltrace -lndpi -lpcap -lm -pthread"

# Install Rust toolchain for yara-x
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Build and install yara-x v1.14.0 C API library
RUN cd /tmp && \
    wget https://github.com/VirusTotal/yara-x/archive/refs/tags/v1.14.0.tar.gz && \
    busybox tar xfz v1.14.0.tar.gz && \
    cd yara-x-1.14.0 && \
    cargo build --release -p yara-x-capi && \
    cp target/release/libyara_x_capi.so /usr/local/lib/ && \
    cp target/release/libyara_x_capi.a /usr/local/lib/ && \
    mkdir -p /usr/local/include && \
    cp capi/include/yara_x.h /usr/local/include/ && \
    ldconfig && \
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

# Fail here rather than in every downstream netcap build.
#
# Unlike the alpine builders these steps are not masked -- curl is installed, so
# the rustup pipeline runs, and there is no `|| true` swallowing the chain. But
# nothing asserted the artefacts existed either, and that absence is what let the
# equivalent alpine breakage survive unnoticed through every build. Cheap to
# check, and it fails at the step that caused it.
RUN test -f /usr/local/include/yara_x.h || (echo "yara_x.h missing" && exit 1) && \
    test -f /usr/local/lib/libyara_x_capi.so || (echo "libyara_x_capi.so missing" && exit 1) && \
    test -f /usr/local/lib/libyara_x_capi.a || (echo "libyara_x_capi.a missing" && exit 1)


# Set working directory
WORKDIR /workspace

# Verify Go installation
RUN go version && test "$(go env GOVERSION)" = go1.27.1

# Verify libraries are installed
RUN ldconfig -p | grep -E '(ndpi|trace|proto)'

# This image is ready to accept source code and build with DPI support
CMD ["/bin/bash"]
