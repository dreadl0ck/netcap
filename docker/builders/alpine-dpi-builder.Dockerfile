# Base Alpine builder image for netcap musl builds with DPI support
# This image contains all build dependencies including nDPI and libprotoident
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

# Verify libraries are installed
RUN ldconfig -p 2>/dev/null || true

# This image is ready to accept source code and build with DPI support
CMD ["/bin/sh"]

