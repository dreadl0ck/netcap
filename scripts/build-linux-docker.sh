#!/bin/bash
# Build Linux binaries using Docker
# This script is called by goreleaser before hooks

set -e

# Allow skipping Docker build via environment variable
if [ "${SKIP_DOCKER_BUILD}" = "1" ]; then
    echo "==> Skipping Linux Docker build (SKIP_DOCKER_BUILD=1)"
    exit 0
fi

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "==> Warning: Docker not found, skipping Linux builds"
    echo "    Install Docker to build Linux binaries automatically"
    exit 0
fi

# Check if Docker is running
if ! docker ps &> /dev/null; then
    echo "==> Warning: Docker is not running, skipping Linux builds"
    echo "    Start Docker to build Linux binaries automatically"
    exit 0
fi

echo "==> Building Linux binaries via Docker..."

# Build the Docker image if it doesn't exist or if Dockerfile changed
DOCKER_IMAGE="netcap-builder:latest"
if [[ ! "$(docker images -q ${DOCKER_IMAGE} 2> /dev/null)" ]] || [[ "Dockerfile.goreleaser" -nt ".docker-build-timestamp" ]]; then
    echo "==> Building Docker image..."
    docker build --platform linux/amd64 -f Dockerfile.goreleaser -t ${DOCKER_IMAGE} .
    touch .docker-build-timestamp
else
    echo "==> Using cached Docker image"
fi

# Run goreleaser for Linux in Docker
echo "==> Running goreleaser for Linux builds..."
docker run --rm --platform linux/amd64 \
    -v "$PWD":/workspace \
    -w /workspace \
    ${DOCKER_IMAGE} \
    goreleaser release --config .goreleaser-linux.yml --snapshot --clean --skip-publish --skip-validate

# Copy Linux artifacts to main dist directory
echo "==> Copying Linux artifacts to dist directory..."
if [ -d "dist-linux" ]; then
    # Copy tar.gz files
    if ls dist-linux/*.tar.gz 1> /dev/null 2>&1; then
        cp -v dist-linux/*.tar.gz dist/
    fi
    
    # Merge checksums
    if [ -f "dist-linux/checksums.txt" ]; then
        cat dist-linux/checksums.txt >> dist/checksums.txt
        echo "==> Merged Linux checksums"
    fi
    
    # Copy artifacts.json if exists
    if [ -f "dist-linux/artifacts.json" ]; then
        echo "==> Linux artifacts.json created"
    fi
fi

echo "==> Linux build completed successfully!"

