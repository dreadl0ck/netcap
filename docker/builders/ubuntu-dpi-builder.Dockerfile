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

# Install Go 1.25.1 manually
RUN wget https://go.dev/dl/go1.25.1.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz && \
    rm go1.25.1.linux-amd64.tar.gz

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

# Set working directory
WORKDIR /workspace

# Verify Go installation
RUN go version

# Verify libraries are installed
RUN ldconfig -p | grep -E '(ndpi|trace|proto)'

# This image is ready to accept source code and build with DPI support
CMD ["/bin/bash"]

