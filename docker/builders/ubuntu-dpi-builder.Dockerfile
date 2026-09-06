# Base Ubuntu builder image for netcap glibc builds with DPI support
# This image contains all build dependencies including nDPI and libprotoident
ARG TARGETPLATFORM=linux/amd64
FROM --platform=$TARGETPLATFORM ubuntu:18.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Clean and update package lists
RUN apt-get clean && \
    apt-get update && \
    apt-get install -y \
    software-properties-common \
    net-tools \
    wget \
    curl \
    apt-transport-https \
    lsb-release \
    autogen \
    autoconf \
    automake \
    libtool \
    gcc \
    libpcap-dev \
    linux-headers-generic \
    git \
    vim \
    pkg-config \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install Go 1.27.0, verified against the go.dev release checksum.
RUN wget https://go.dev/dl/go1.27.0.linux-amd64.tar.gz && \
    echo '675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685  go1.27.0.linux-amd64.tar.gz' | sha256sum -c - && \
    tar -C /usr/local -xzf go1.27.0.linux-amd64.tar.gz && \
    rm go1.27.0.linux-amd64.tar.gz

# Set Go environment
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Install libwandio, libtrace, libflowmanager, and libprotoident from cloudsmith
RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libwandio/cfg/setup/bash.deb.sh' | bash && \
    curl -1sLf 'https://dl.cloudsmith.io/public/wand/libwandder/cfg/setup/bash.deb.sh' | bash && \
    curl -1sLf 'https://dl.cloudsmith.io/public/wand/libtrace/cfg/setup/bash.deb.sh' | bash && \
    curl -1sLf 'https://dl.cloudsmith.io/public/wand/libflowmanager/cfg/setup/bash.deb.sh' | bash && \
    curl -1sLf 'https://dl.cloudsmith.io/public/wand/libprotoident/cfg/setup/bash.deb.sh' | bash && \
    apt-get update && \
    apt-get install -y \
    liblinear-dev \
    libprotoident \
    libprotoident-dev \
    libprotoident-tools \
    libtrace4-dev \
    libtrace4-tools && \
    rm -rf /var/lib/apt/lists/*

# Install nDPI from source
RUN apt-get update && \
    apt-get install -y libjson-c-dev && \
    rm -rf /var/lib/apt/lists/* && \
    wget https://github.com/ntop/nDPI/archive/4.14.tar.gz && \
    tar xfz 4.14.tar.gz && \
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
    tar xfz v1.14.0.tar.gz && \
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
RUN go version && test "$(go env GOVERSION)" = go1.27.0

# Verify libraries are installed
RUN ldconfig -p | grep -E '(ndpi|trace|proto)'

# This image is ready to accept source code and build with DPI support
CMD ["/bin/bash"]

