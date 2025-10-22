#!/bin/bash
#
# Build script for Netcap Database Server Docker container
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

IMAGE_NAME="${IMAGE_NAME:-netcap-dbs-server}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

echo "Building Netcap Database Server Docker image..."
echo "  Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "  Context: ${PROJECT_ROOT}"
echo ""

# Build the image
docker build \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    "${PROJECT_ROOT}"

echo ""
echo "Build completed successfully!"
echo ""
echo "To run the container:"
echo "  docker run -d -p 8080:8080 -v netcap-dbs-data:/data ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "Or using docker-compose:"
echo "  cd ${SCRIPT_DIR} && docker-compose up -d"
echo ""

