#!/bin/bash
#
# Run the Netcap Service Mode container locally for testing
#

set -e

# Image configuration
IMAGE_NAME="netcap-service"
VERSION="${VERSION:-latest}"
CONTAINER_NAME="${CONTAINER_NAME:-netcap-service-local}"

# Registry from environment variable, default to Docker Hub
REGISTRY="${NETCAP_CONTAINER_REGISTRY:-docker.io}"
REGISTRY_USER="${NETCAP_CONTAINER_REGISTRY_USER:-dreadl0ck}"

# Full image tag
if [[ "$REGISTRY" == "docker.io" || "$REGISTRY" == "" ]]; then
    IMAGE_TAG="${REGISTRY_USER}/${IMAGE_NAME}:${VERSION}"
else
    IMAGE_TAG="${REGISTRY}/${IMAGE_NAME}:${VERSION}"
fi

# Port configuration
HTTP_PORT="${HTTP_PORT:-7070}"

# Data directory for persistent storage
DATA_DIR="${DATA_DIR:-$HOME/.netcap/service-data}"

# Config directory for persistent configuration
CONFIG_DIR="${CONFIG_DIR:-$HOME/.config/netcap-service}"

# Environment variables for the container
NC_DPI="${NC_DPI:-true}"
NC_MAX_FILE_SIZE="${NC_MAX_FILE_SIZE:-104857600}"     # 100MB
NC_MAX_ANALYSIS_HOUR="${NC_MAX_ANALYSIS_HOUR:-10}"
NC_SESSION_EXPIRY="${NC_SESSION_EXPIRY:-60}"          # minutes
NC_CLEANUP_INTERVAL="${NC_CLEANUP_INTERVAL:-10}"      # minutes

echo "[INFO] Running Netcap Service Mode container locally"
echo "[INFO] Image: ${IMAGE_TAG}"
echo "[INFO] Container name: ${CONTAINER_NAME}"
echo "[INFO] HTTP Port: ${HTTP_PORT}"
echo "[INFO] Data directory: ${DATA_DIR}"
echo "[INFO] Config directory: ${CONFIG_DIR}"
echo "[INFO] DPI enabled: ${NC_DPI}"
echo ""

# Pull the latest image
echo "[INFO] Pulling latest image ${IMAGE_TAG}..."
if docker pull "${IMAGE_TAG}"; then
    echo "[INFO] ✓ Image pulled successfully"
else
    echo "[WARNING] Failed to pull image from registry"
    echo "[INFO] Checking if image exists locally..."
    if ! docker image inspect "${IMAGE_TAG}" > /dev/null 2>&1; then
        echo "[ERROR] Image not available locally or in registry"
        echo "[INFO] Please build it first with:"
        echo "       zeus build-service"
        echo "       or"
        echo "       zeus build-service-local-dpi"
        exit 1
    fi
    echo "[INFO] Using existing local image"
fi
echo ""

# Stop and remove existing container if it exists
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "[INFO] Found existing container ${CONTAINER_NAME}"
    
    # Check if it's running and stop it
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo "[INFO] Stopping running container..."
        docker stop "${CONTAINER_NAME}" > /dev/null
        echo "[INFO] ✓ Container stopped"
    fi
    
    # Remove the container
    echo "[INFO] Removing old container..."
    docker rm "${CONTAINER_NAME}" > /dev/null
    echo "[INFO] ✓ Container removed"
    echo ""
fi

# Create data directory if it doesn't exist and set permissions
mkdir -p "${DATA_DIR}"

# Set ownership on data directory (container runs as UID 1000)
chown -R 1000:1000 "${DATA_DIR}" 2>/dev/null || {
    echo "[WARNING] Failed to set ownership on ${DATA_DIR}"
    echo "[INFO] You may need to run: sudo chown -R 1000:1000 ${DATA_DIR}"
}

# Create config directory if it doesn't exist and set permissions
mkdir -p "${CONFIG_DIR}"
chown -R 1000:1000 "${CONFIG_DIR}" 2>/dev/null || {
    echo "[WARNING] Failed to set ownership on ${CONFIG_DIR}"
    echo "[INFO] You may need to run: sudo chown -R 1000:1000 ${CONFIG_DIR}"
}

# Run the container
echo "[INFO] Creating and starting new container..."
docker run -d \
    --name "${CONTAINER_NAME}" \
    --restart unless-stopped \
    -p "${HTTP_PORT}:7070" \
    -v "${DATA_DIR}:/data" \
    -v "${CONFIG_DIR}:/home/netcap/.config/netcap" \
    -e NC_DATA_DIR=/data/netcap-service \
    -e NC_HTTP=0.0.0.0:7070 \
    -e NC_DPI="${NC_DPI}" \
    -e NC_MAX_FILE_SIZE="${NC_MAX_FILE_SIZE}" \
    -e NC_MAX_ANALYSIS_HOUR="${NC_MAX_ANALYSIS_HOUR}" \
    -e NC_SESSION_EXPIRY="${NC_SESSION_EXPIRY}" \
    -e NC_CLEANUP_INTERVAL="${NC_CLEANUP_INTERVAL}" \
    -e TZ=UTC \
    "${IMAGE_TAG}"

echo ""
echo "[INFO] ✓ Container created and started successfully!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Netcap Service Mode - Web UI"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  🌐 Web UI:            http://localhost:${HTTP_PORT}"
echo "  📊 Health Check:      http://localhost:${HTTP_PORT}/health"
echo "  📁 Data Directory:    ${DATA_DIR}"
echo "  📦 Preloaded PCAPs:   ${DATA_DIR}/pcaps"
echo "  ⚙️  Config Directory:  ${CONFIG_DIR}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "💡 Tip: Place PCAP files in ${DATA_DIR}/pcaps/ to have them"
echo "   automatically analyzed on container startup and visible to all users."
echo ""
echo "Useful commands:"
echo ""
echo "  View logs:          docker logs -f ${CONTAINER_NAME}"
echo "  Stop container:     docker stop ${CONTAINER_NAME}"
echo "  Remove container:   docker rm ${CONTAINER_NAME}"
echo "  Restart container:  docker restart ${CONTAINER_NAME}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Open browser (optional)
if [[ "${OPEN_BROWSER}" == "true" ]]; then
    sleep 2
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "http://localhost:${HTTP_PORT}"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open "http://localhost:${HTTP_PORT}" 2>/dev/null || true
    fi
fi

# Optionally follow logs
if [[ "${FOLLOW_LOGS}" == "true" ]]; then
    echo "[INFO] Following container logs (Ctrl+C to exit)..."
    echo ""
    docker logs -f "${CONTAINER_NAME}"
fi

