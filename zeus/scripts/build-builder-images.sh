#!/bin/bash
# Build and push base builder images to accelerate Linux builds
# These images contain all dependencies and can be reused across builds

set -e

REGISTRY="${REGISTRY:-dreadl0ck}"
VERSION="${VERSION:-latest}"

echo "[INFO] Building netcap builder images..."
echo "[INFO] Registry: $REGISTRY"
echo "[INFO] Version: $VERSION"

# Function to build and optionally push an image
build_image() {
    local dockerfile=$1
    local tag=$2
    local push=${3:-false}
    
    echo ""
    echo "======================================"
    echo "[INFO] Building $tag"
    echo "======================================"
    
    docker build \
        --platform linux/amd64 \
        -f "$dockerfile" \
        -t "$tag" \
        .
    
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to build $tag"
        return 1
    fi
    
    echo "[INFO] Successfully built $tag"
    
    if [ "$push" = true ]; then
        echo "[INFO] Pushing $tag to registry..."
        docker push "$tag"
        if [ $? -eq 0 ]; then
            echo "[INFO] Successfully pushed $tag"
        else
            echo "[ERROR] Failed to push $tag"
            return 1
        fi
    fi
    
    return 0
}

# Navigate to project root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "[INFO] Script directory: $SCRIPT_DIR"
echo "[INFO] Project root: $PROJECT_ROOT"

cd "$PROJECT_ROOT" || exit 1

# Verify we're in the right place
if [ ! -d "docker/builders" ]; then
    echo "[ERROR] Cannot find docker/builders directory"
    echo "[ERROR] Current directory: $(pwd)"
    exit 1
fi

echo "[INFO] Working directory: $(pwd)"
echo ""

# Build Alpine builder (for musl builds without DPI)
build_image \
    "docker/builders/alpine-builder.Dockerfile" \
    "$REGISTRY/netcap-builder:alpine-$VERSION" \
    ${PUSH:-false}

# Build Alpine DPI builder (for musl builds with DPI support)
build_image \
    "docker/builders/alpine-dpi-builder.Dockerfile" \
    "$REGISTRY/netcap-builder:alpine-dpi-$VERSION" \
    ${PUSH:-false}

# Build Ubuntu builder (for glibc builds without DPI)
build_image \
    "docker/builders/ubuntu-builder.Dockerfile" \
    "$REGISTRY/netcap-builder:ubuntu-$VERSION" \
    ${PUSH:-false}

# Build Ubuntu DPI builder (for glibc builds with DPI support)
build_image \
    "docker/builders/ubuntu-dpi-builder.Dockerfile" \
    "$REGISTRY/netcap-builder:ubuntu-dpi-$VERSION" \
    ${PUSH:-false}

echo ""
echo "======================================"
echo "[INFO] All builder images built successfully!"
echo "======================================"
echo ""
echo "Built images:"
docker images | grep "netcap-builder"
echo ""
echo "To push these images to the registry, run:"
echo "  PUSH=true $0"
echo ""
echo "To use a different registry:"
echo "  REGISTRY=your-registry $0"
echo ""

