# Netcap Database Server - Alpine Linux
# Lightweight container for running the database rebuild service

# Build stage
FROM golang:1.27.0-alpine AS builder

# Install build dependencies (minimal set for nodpi build)
# protobuf/protobuf-dev are required because types/netcap.pb.go is no longer
# tracked in git (commit 8ba92384) and must be regenerated at build time.
RUN apk add --no-cache git gcc musl-dev protobuf protobuf-dev

# Set working directory
WORKDIR /build

# Copy go modules manifests
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Regenerate protobuf code: types/netcap.pb.go is no longer tracked in git
# (see commit 8ba92384). Use gogofaster to match zeus/commands.yml.
RUN go install github.com/gogo/protobuf/protoc-gen-gogofaster@v1.3.2 \
    && PATH="$PATH:$(go env GOPATH)/bin" \
       protoc --gogofaster_out=types/. netcap.proto

# Build the binary with nodpi + noyara tags. The dbs-server does not need
# DPI or YARA scanning; without `noyara` the build fails because
# yara_x_capi.pc / libyara_x_capi are not installed in this image.
# CGO still needed for some dependencies like bleve.
RUN apk add --no-cache libpcap-dev linux-headers
RUN CGO_ENABLED=1 GOOS=linux go build -tags "nodpi noyara" -a -installsuffix cgo -ldflags="-s -w" -o netcap ./cmd

# Runtime stage
FROM alpine:latest

LABEL maintainer="Philipp Mieden <dreadl0ck@protonmail.ch>"
LABEL description="Netcap Database Server - Serves and rebuilds netcap databases nightly"

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    git \
    git-lfs \
    libpcap \
    && git lfs install

# Create netcap user and group
RUN addgroup -g 1000 netcap && \
    adduser -D -u 1000 -G netcap netcap

# Set working directory
WORKDIR /home/netcap

# Copy binary from builder
COPY --from=builder /build/netcap /usr/local/bin/net

# Create data directories
RUN mkdir -p /data/netcap-dbs-server && \
    chown -R netcap:netcap /data

# Switch to netcap user
USER netcap

# Expose HTTP port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Set environment variables
ENV NC_CONFIG_ROOT=/data/netcap-dbs-server
ENV NETCAP_DBS_URL=http://localhost:8080

# Volume for persistent data
VOLUME ["/data"]

# Run the database server
CMD ["net", "util", "-serve-dbs", "-serve-addr", ":8080", "-verbose"]

