#!/bin/bash
#
# Build and push the Netcap Service Mode container
#

set -e

# Image configuration
IMAGE_NAME="netcap-service"
VERSION="${VERSION:-latest}"

# Registry from environment variable, default to Docker Hub
REGISTRY="${NETCAP_CONTAINER_REGISTRY:-docker.io}"
REGISTRY_USER="${NETCAP_CONTAINER_REGISTRY_USER:-dreadl0ck}"

# Full image tag
if [[ "$REGISTRY" == "docker.io" || "$REGISTRY" == "" ]]; then
    # Docker Hub format: username/image:tag
    IMAGE_TAG="${REGISTRY_USER}/${IMAGE_NAME}:${VERSION}"
else
    # Other registries: registry/image:tag
    IMAGE_TAG="${REGISTRY}/${IMAGE_NAME}:${VERSION}"
fi

echo "[INFO] Building netcap service mode container"
echo "[INFO] Image: ${IMAGE_TAG}"
echo "[INFO] Registry: ${REGISTRY}"
echo "[INFO] Version: ${VERSION}"

# Check if frontend assets exist
if [ ! -d "cmd/capture/webui/frontend/out" ]; then
    echo "[ERROR] Frontend assets not found at cmd/capture/webui/frontend/out"
    echo "[INFO] Please build the frontend first:"
    echo "       zeus build-frontend"
    echo "       (or manually: cd cmd/capture/webui/frontend && npm install && npm run build)"
    exit 1
fi

# Check if we should build multi-platform images
PLATFORMS="${NETCAP_PLATFORMS:-linux/amd64,linux/arm64}"
USE_BUILDX="${NETCAP_USE_BUILDX:-true}"

# Check if docker/service directory exists
if [ -d "docker/service" ]; then
    DOCKER_DIR="docker/service"
else
    echo "[ERROR] docker/service directory not found"
    exit 1
fi

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
    docker buildx build \
        --platform "${PLATFORMS}" \
        --build-arg VERSION="${VERSION}" \
        -t "${IMAGE_TAG}" \
        -f Dockerfile \
        --push \
        ../..
    
    if (( $? != 0 )); then
        echo "[ERROR] Building container failed"
        exit 1
    fi
    
    # Also tag and push as latest if building a version
    if [[ "$VERSION" != "latest" ]]; then
        LATEST_TAG="${REGISTRY_USER}/${IMAGE_NAME}:latest"
        if [[ "$REGISTRY" != "docker.io" && "$REGISTRY" != "" ]]; then
            LATEST_TAG="${REGISTRY}/${IMAGE_NAME}:latest"
        fi
        
        echo "[INFO] Building and pushing latest tag for: ${PLATFORMS}"
        docker buildx build \
            --platform "${PLATFORMS}" \
            --build-arg VERSION="${VERSION}" \
            -t "${LATEST_TAG}" \
            -f Dockerfile \
            --push \
            ../..
    fi
    
    echo "[INFO] Successfully built and pushed multi-platform ${IMAGE_TAG}"
else
    # Standard single-platform build for local use
    echo "[INFO] Building single-platform image for current architecture"
    docker build \
        --build-arg VERSION="${VERSION}" \
        -t "${IMAGE_TAG}" \
        -f Dockerfile \
        ../..
    
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
        if [[ "$REGISTRY" != "docker.io" && "$REGISTRY" != "" ]]; then
            LATEST_TAG="${REGISTRY}/${IMAGE_NAME}:latest"
        fi
        
        echo "[INFO] Tagging as latest: ${LATEST_TAG}"
        docker tag "${IMAGE_TAG}" "${LATEST_TAG}"
    fi

    # Push to registry if NETCAP_PUSH_IMAGES is set (for non-buildx builds)
    if [[ "${NETCAP_PUSH_IMAGES}" == "true" ]]; then
        echo "[INFO] Pushing container to registry: ${REGISTRY}"
        
        docker push "${IMAGE_TAG}"
        
        if (( $? != 0 )); then
            echo "[ERROR] Pushing container failed"
            echo "[INFO] Make sure you are logged in to the registry:"
            echo "       docker login ${REGISTRY}"
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
echo "Or using docker-compose:"
echo "  cd docker/service"
echo "  docker-compose up -d"
echo ""
echo "Container runs: net capture --service -http :7070"
echo ""
echo "To build and push multi-platform images:"
echo "  export NETCAP_PUSH_IMAGES=true"
echo "  zeus build-service"
echo ""
echo "To customize platforms (default: linux/amd64,linux/arm64):"
echo "  export NETCAP_PLATFORMS=linux/amd64,linux/arm64,linux/arm/v7"
echo ""
echo "To disable multi-platform build (single platform only):"
echo "  export NETCAP_USE_BUILDX=false"
echo ""
echo "Access the service at: http://localhost:7070"


