# Base Ubuntu builder image for netcap glibc builds (without DPI support)
# This image contains all build dependencies and can be reused across builds
ARG TARGETPLATFORM=linux/amd64
FROM --platform=$TARGETPLATFORM ubuntu:18.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Clean and update package lists
RUN apt-get clean && \
    apt-get update && \
    apt-get install -y \
    software-properties-common \
    wget \
    curl \
    apt-transport-https \
    lsb-release \
    autogen \
    autoconf \
    libtool \
    gcc \
    libpcap-dev \
    linux-headers-generic \
    git \
    vim \
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

# Set working directory
WORKDIR /workspace

# Verify Go installation
RUN go version

# This image is ready to accept source code and build
CMD ["/bin/bash"]

