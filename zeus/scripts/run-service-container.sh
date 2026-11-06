#!/bin/bash
#
# Run the Netcap Service Mode container locally for testing
#

set -e

# Validate before pulling images or replacing an existing container.
trust_args=()
if [[ -n "${NC_DBS_APPROVALS:-}${NC_DBS_APPROVALS_SHA256:-}" ]]; then
if [[ -z "${NC_DBS_APPROVALS:-}" || ! "$NC_DBS_APPROVALS" = /* || ! -f "$NC_DBS_APPROVALS" || -L "$NC_DBS_APPROVALS" || ! -r "$NC_DBS_APPROVALS" ]]; then
    echo "[ERROR] Set NC_DBS_APPROVALS to an absolute, readable regular registry file outside the database directory." >&2
    exit 1
fi
if [[ "$NC_DBS_APPROVALS" = *','* || "$NC_DBS_APPROVALS" = *$'\n'* ]]; then
    echo "[ERROR] NC_DBS_APPROVALS cannot contain commas or newlines in a Docker bind mount." >&2
    exit 1
fi
if [[ ! "${NC_DBS_APPROVALS_SHA256:-}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "[ERROR] Set NC_DBS_APPROVALS_SHA256 to the independently obtained lowercase SHA-256 registry pin." >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    registry_digest=$(sha256sum < "$NC_DBS_APPROVALS")
elif command -v shasum >/dev/null 2>&1; then
    registry_digest=$(shasum -a 256 < "$NC_DBS_APPROVALS")
else
    echo "[ERROR] Install sha256sum or shasum to verify the supplied registry pin." >&2
    exit 1
fi
if [[ "${registry_digest%% *}" != "$NC_DBS_APPROVALS_SHA256" ]]; then
    echo "[ERROR] Approval registry digest mismatch; check the file against the independently supplied NC_DBS_APPROVALS_SHA256." >&2
    exit 1
fi
trust_args=(--mount "type=bind,source=${NC_DBS_APPROVALS},target=/run/netcap-trust/approvals.json,readonly"
    -e NC_DBS_APPROVALS=/run/netcap-trust/approvals.json
    -e NC_DBS_APPROVALS_SHA256="${NC_DBS_APPROVALS_SHA256}")
fi

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
    "${trust_args[@]}" \
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
