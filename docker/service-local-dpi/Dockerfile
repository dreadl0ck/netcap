# Netcap Try Service - Alpine Linux (with local go-dpi)
# Container for running the try service with file upload capabilities (with DPI support using local go-dpi)

# Build stage - Use official netcap builder with DPI support
FROM --platform=linux/amd64 dreadl0ck/netcap-builder:alpine-dpi-latest AS builder

# Copy go-dpi source FIRST (to use local version)
WORKDIR /go-dpi
COPY go-dpi/ .

# Copy netcap source
WORKDIR /netcap
COPY . .

# Accept VERSION as a build argument (defaults to 0.7.7 if not provided)
ARG VERSION=0.7.7

# Add replace directive to use local go-dpi
RUN echo "replace github.com/dreadl0ck/go-dpi => /go-dpi" >> go.mod

# Clear Go build cache to ensure fresh build
RUN go clean -cache -modcache -i -r

# Remove any existing binary
RUN rm -rf /netcap/bin

# Build the binary WITH DPI support (disable workspace mode)
# Extract library versions
RUN GOPACKET_VERSION=$(grep "github.com/gopacket/gopacket" /netcap/go.mod | grep -v indirect | awk '{print $2}') && \
    GO_DPI_VERSION=$(cd /go-dpi && git describe --tags --always 2>/dev/null || echo "local-dev") && \
    mkdir -p /netcap/bin && \
    GOWORK=off GOOS=linux GOARCH=amd64 go build -a -trimpath \
    -ldflags "-r /usr/local/lib -s -w \
        -X github.com/dreadl0ck/netcap.Version=v${VERSION} \
        -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION} \
        -X github.com/dreadl0ck/netcap/dpi.NDPIVersion=4.14.0 \
        -X github.com/dreadl0ck/netcap/dpi.LibprotoidentVersion=2.0.15-1 \
        -X github.com/dreadl0ck/netcap/dpi.GoDPIVersion=${GO_DPI_VERSION}" \
    -o /netcap/bin/netcap github.com/dreadl0ck/netcap/cmd

# Runtime stage
FROM --platform=linux/amd64 alpine:latest

LABEL maintainer="Philipp Mieden <dreadl0ck@protonmail.ch>"
LABEL description="Netcap Service Mode - Upload and analyze PCAP files (with local go-dpi)"

# Install runtime dependencies including DPI libraries
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    libpcap \
    tcpdump \
    libcap \
    iptables \
    libnetfilter_queue \
    libstdc++ \
    libgcc \
    json-c

# Give tcpdump the necessary capabilities to read pcap files without root
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump

# Create netcap user and group (non-root)
RUN addgroup -g 1000 netcap && \
    adduser -D -u 1000 -G netcap netcap

# Set working directory
WORKDIR /home/netcap

# Copy binary and DPI libraries from builder
COPY --from=builder /netcap/bin/netcap /usr/local/bin/net
COPY --from=builder /usr/lib/* /usr/lib/
COPY --from=builder /usr/local/lib/* /usr/local/lib/

# Run ldconfig to register the shared libraries and set up the dynamic linker cache
RUN ldconfig /usr/lib /usr/local/lib || true

# Set LD_LIBRARY_PATH to ensure runtime linker finds nDPI and other DPI libraries
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:${LD_LIBRARY_PATH}

# Copy entrypoint script
COPY docker/service/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Create data directories with proper permissions
RUN mkdir -p /data/netcap-service && \
    mkdir -p /home/netcap/.config/netcap && \
    chown -R netcap:netcap /data /home/netcap

# Switch to netcap user (non-root)
USER netcap

# Expose HTTP port
EXPOSE 7070

# Health check
# HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
#     CMD curl -f http://localhost:7070/health || exit 1

# Set environment variables
ENV NC_DATA_DIR=/data/netcap-service
ENV NC_HTTP=0.0.0.0:7070

# Volume for persistent data
VOLUME ["/data"]

# Use entrypoint script to bootstrap databases
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

