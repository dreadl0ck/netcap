#!/bin/bash
# Publish new candidates; release consumers select a qualified digest separately.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../.."
: "${BUILDER_VERSION:?set a unique candidate suffix, for example yara1.22.0-<revision>-<date>}"
[[ "$BUILDER_VERSION" =~ ^yara1\.22\.0-[0-9a-f]{8,40}-[0-9]{8}(-[a-z0-9]+)?$ ]] || {
    echo 'BUILDER_VERSION must identify a new matched YARA-X 1.22.0 candidate' >&2
    exit 1
}
REGISTRY="${REGISTRY:-dreadl0ck}"
[[ "$REGISTRY" == dreadl0ck || "$REGISTRY" == docker.io/dreadl0ck ]] || {
    echo 'This publisher checks candidate uniqueness in docker.io/dreadl0ck' >&2
    exit 1
}

for variant in alpine alpine-dpi ubuntu ubuntu-dpi; do
    tag="$REGISTRY/netcap-builder:$variant-$BUILDER_VERSION"
    python3 "$SCRIPT_DIR/builder-image.py" --ensure-absent "$tag"
done

for variant in alpine alpine-dpi ubuntu ubuntu-dpi; do
    tag="$REGISTRY/netcap-builder:$variant-$BUILDER_VERSION"
    docker build --platform linux/amd64 \
        -f "docker/builders/$variant-builder.Dockerfile" -t "$tag" .
    docker run --rm --cpus=2 --network=none "$tag" \
        pkg-config --exact-version=1.22.0 yara_x_capi
    if [[ "${PUSH:-false}" == true ]]; then
        python3 "$SCRIPT_DIR/builder-image.py" --ensure-absent "$tag"
        docker push "$tag"
        docker buildx imagetools inspect "$tag"
    fi
done
