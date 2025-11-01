#!/bin/bash
#
# Build and push the Netcap Service Mode container with local go-dpi
#

set -e

# Get the netcap root directory (parent of zeus directory)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
NETCAP_ROOT="$( cd "${SCRIPT_DIR}/../.." && pwd )"

# Image configuration
IMAGE_NAME="netcap-service"
VERSION="${VERSION:-latest}"

# Registry from environment variable, default to Docker Hub only
REGISTRY_USER="${NETCAP_REGISTRY_USER:-dreadl0ck}"

# Local go-dpi path (default to ../go-dpi)
GO_DPI_PATH="${GO_DPI_PATH:-../go-dpi}"

# Full image tag - Docker Hub only
IMAGE_TAG="${REGISTRY_USER}/${IMAGE_NAME}:${VERSION}"

echo "[INFO] Building netcap service mode container with local go-dpi"
echo "[INFO] Image: ${IMAGE_TAG}"
echo "[INFO] Registry: Docker Hub"
echo "[INFO] Version: ${VERSION}"
echo "[INFO] Local go-dpi path: ${GO_DPI_PATH}"

# Check if frontend assets exist
if [ ! -d "$NETCAP_ROOT/cmd/capture/webui/frontend/out" ]; then
    echo "[ERROR] Frontend assets not found at $NETCAP_ROOT/cmd/capture/webui/frontend/out"
    echo "[INFO] Please build the frontend first:"
    echo "       zeus build-frontend"
    echo "       (or manually: cd cmd/capture/webui/frontend && npm install && npm run build)"
    exit 1
fi

# Verify go-dpi path exists
if [ ! -d "$GO_DPI_PATH" ]; then
    echo "[ERROR] Local go-dpi directory not found at: $GO_DPI_PATH"
    echo "[INFO] Please set GO_DPI_PATH to the correct path:"
    echo "       GO_DPI_PATH=/path/to/go-dpi zeus build-service-local-dpi"
    exit 1
fi

# Get absolute path to go-dpi
GO_DPI_ABS_PATH=$(cd "$GO_DPI_PATH" && pwd)
echo "[INFO] Using go-dpi from: ${GO_DPI_ABS_PATH}"

# Check if we should build multi-platform images
PLATFORMS="${NETCAP_PLATFORMS:-linux/amd64,linux/arm64}"
USE_BUILDX="${NETCAP_USE_BUILDX:-true}"

# Check if docker/service-local-dpi directory exists, create if needed
if [ ! -d "$NETCAP_ROOT/docker/service-local-dpi" ]; then
    echo "[INFO] Creating docker/service-local-dpi directory..."
    mkdir -p "$NETCAP_ROOT/docker/service-local-dpi"
fi

# Create Dockerfile for local DPI build if it doesn't exist or needs updating
cat > "$NETCAP_ROOT/docker/service-local-dpi/Dockerfile" << 'DOCKERFILE_END'
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
    GOWORK=off GOOS=linux GOARCH=amd64 go build -a \
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
    iptables \
    libnetfilter_queue \
    libstdc++ \
    libgcc \
    json-c

# Create netcap user and group (non-root)
RUN addgroup -g 1000 netcap && \
    adduser -D -u 1000 -G netcap netcap

# Set working directory
WORKDIR /home/netcap

# Copy binary and DPI libraries from builder
COPY --from=builder /netcap/bin/netcap /usr/local/bin/netcap
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

DOCKERFILE_END

echo "[INFO] Created/updated Dockerfile at docker/service-local-dpi/Dockerfile"

DOCKER_DIR="$NETCAP_ROOT/docker/service-local-dpi"

cd "$DOCKER_DIR"

if [[ "${USE_BUILDX}" == "true" && "${NETCAP_PUSH_IMAGES}" == "true" ]]; then
    # Use buildx for multi-platform builds (only when pushing)
    echo "[INFO] Building multi-platform image for: ${PLATFORMS}"
    
    # Ensure buildx builder exists
    if ! docker buildx inspect netcap-builder > /dev/null 2>&1; then
        echo "[INFO] Creating buildx builder 'netcap-builder'"
        docker buildx create --name netcap-builder --use
    else
        docker buildx use netcap-builder
    fi
    
    # Build and push multi-platform image
    # Note: We need to create a temporary context with go-dpi
    BUILD_CONTEXT=$(mktemp -d)
    trap "rm -rf $BUILD_CONTEXT" EXIT
    
    echo "[INFO] Preparing build context..."
    echo "[INFO] Copying only necessary files for build..."
    
    # Copy Go source files and build essentials
    cd "$NETCAP_ROOT"
    find . -name "*.go" -type f -exec sh -c 'mkdir -p "'$BUILD_CONTEXT'/$(dirname {})" && cp {} "'$BUILD_CONTEXT'/{}"' \;
    
    # Copy Go module files
    cp go.mod go.sum "$BUILD_CONTEXT/"
    [ -f go.work ] && cp go.work "$BUILD_CONTEXT/"
    [ -f go.work.sum ] && cp go.work.sum "$BUILD_CONTEXT/"
    
    # Copy proto files if any
    find . -name "*.proto" -type f -exec sh -c 'mkdir -p "'$BUILD_CONTEXT'/$(dirname {})" && cp {} "'$BUILD_CONTEXT'/{}"' \;
    
    # Copy frontend build output
    if [ -d "cmd/capture/webui/frontend/out" ]; then
        mkdir -p "$BUILD_CONTEXT/cmd/capture/webui/frontend"
        cp -r cmd/capture/webui/frontend/out "$BUILD_CONTEXT/cmd/capture/webui/frontend/"
    fi
    
    # Copy entrypoint script
    mkdir -p "$BUILD_CONTEXT/docker/service"
    cp docker/service/entrypoint.sh "$BUILD_CONTEXT/docker/service/"
    
    echo "[INFO] Copying go-dpi source from $GO_DPI_ABS_PATH..."
    cp -r "$GO_DPI_ABS_PATH" "$BUILD_CONTEXT/go-dpi"
    
    echo "[INFO] Building container..."
    docker buildx build \
        --platform "${PLATFORMS}" \
        --build-arg VERSION="${VERSION}" \
        -t "${IMAGE_TAG}" \
        -f "$NETCAP_ROOT/docker/service-local-dpi/Dockerfile" \
        --push \
        "$BUILD_CONTEXT"
    
    if (( $? != 0 )); then
        echo "[ERROR] Building container failed"
        exit 1
    fi
    
    # Also tag and push as latest if building a version
    if [[ "$VERSION" != "latest" ]]; then
        LATEST_TAG="${REGISTRY_USER}/${IMAGE_NAME}:latest"
        
        echo "[INFO] Building and pushing latest tag for: ${PLATFORMS}"
        docker buildx build \
            --platform "${PLATFORMS}" \
            --build-arg VERSION="${VERSION}" \
            -t "${LATEST_TAG}" \
            -f "$NETCAP_ROOT/docker/service-local-dpi/Dockerfile" \
            --push \
            "$BUILD_CONTEXT"
    fi
    
    echo "[INFO] Successfully built and pushed multi-platform ${IMAGE_TAG}"
else
    # Standard single-platform build for local use
    echo "[INFO] Building single-platform image for current architecture"
    
    # Create a temporary build context
    BUILD_CONTEXT=$(mktemp -d)
    trap "rm -rf $BUILD_CONTEXT" EXIT
    
    echo "[INFO] Preparing build context..."
    echo "[INFO] Copying only necessary files for build..."
    
    # Copy Go source files and build essentials
    cd "$NETCAP_ROOT"
    find . -name "*.go" -type f -exec sh -c 'mkdir -p "'$BUILD_CONTEXT'/$(dirname {})" && cp {} "'$BUILD_CONTEXT'/{}"' \;
    
    # Copy Go module files
    cp go.mod go.sum "$BUILD_CONTEXT/"
    [ -f go.work ] && cp go.work "$BUILD_CONTEXT/"
    [ -f go.work.sum ] && cp go.work.sum "$BUILD_CONTEXT/"
    
    # Copy proto files if any
    find . -name "*.proto" -type f -exec sh -c 'mkdir -p "'$BUILD_CONTEXT'/$(dirname {})" && cp {} "'$BUILD_CONTEXT'/{}"' \;
    
    # Copy frontend build output
    if [ -d "cmd/capture/webui/frontend/out" ]; then
        mkdir -p "$BUILD_CONTEXT/cmd/capture/webui/frontend"
        cp -r cmd/capture/webui/frontend/out "$BUILD_CONTEXT/cmd/capture/webui/frontend/"
    fi
    
    # Copy entrypoint script
    mkdir -p "$BUILD_CONTEXT/docker/service"
    cp docker/service/entrypoint.sh "$BUILD_CONTEXT/docker/service/"
    
    echo "[INFO] Copying go-dpi source from $GO_DPI_ABS_PATH..."
    cp -r "$GO_DPI_ABS_PATH" "$BUILD_CONTEXT/go-dpi"
    
    docker build \
        --build-arg VERSION="${VERSION}" \
        -t "${IMAGE_TAG}" \
        -f "$NETCAP_ROOT/docker/service-local-dpi/Dockerfile" \
        "$BUILD_CONTEXT"
    
    if (( $? != 0 )); then
        echo "[ERROR] Building container failed"
        exit 1
    fi
    
    echo "[INFO] Successfully built ${IMAGE_TAG}"
fi

# Handle local builds (non-buildx)
if [[ "${USE_BUILDX}" != "true" || "${NETCAP_PUSH_IMAGES}" != "true" ]]; then
    # Also tag as 'latest' if building a version
    if [[ "$VERSION" != "latest" ]]; then
        LATEST_TAG="${REGISTRY_USER}/${IMAGE_NAME}:latest"
        
        echo "[INFO] Tagging as latest: ${LATEST_TAG}"
        docker tag "${IMAGE_TAG}" "${LATEST_TAG}"
    fi

    # Push to registry if NETCAP_PUSH_IMAGES is set (for non-buildx builds)
    if [[ "${NETCAP_PUSH_IMAGES}" == "true" ]]; then
        echo "[INFO] Pushing container to Docker Hub"
        
        docker push "${IMAGE_TAG}"
        
        if (( $? != 0 )); then
            echo "[ERROR] Pushing container failed"
            echo "[INFO] Make sure you are logged in to Docker Hub:"
            echo "       docker login docker.io"
            exit 1
        fi
        
        echo "[INFO] ✓ Successfully pushed ${IMAGE_TAG}"
        
        # Push latest tag as well
        if [[ "$VERSION" != "latest" ]]; then
            echo "[INFO] Pushing latest tag..."
            docker push "${LATEST_TAG}"
            echo "[INFO] ✓ Successfully pushed ${LATEST_TAG}"
        fi
    else
        echo "[INFO] Skipping push (set NETCAP_PUSH_IMAGES=true to push)"
        echo "[INFO] To push manually, run:"
        echo "       docker push ${IMAGE_TAG}"
    fi
fi

echo "[INFO] Container image details:"
docker images "${IMAGE_TAG}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"

echo "[INFO] Done!"
echo ""
echo "To run the container locally:"
echo "  docker run -d -p 7070:7070 -v netcap-service-data:/data ${IMAGE_TAG}"
echo ""
echo "Container runs: net capture --service -http :7070"
echo ""
echo "This container was built with local go-dpi from: ${GO_DPI_ABS_PATH}"
echo ""
echo "Access the service at: http://localhost:7070"


