#!/bin/sh
set -e

echo "[Netcap Service Mode] Starting..."

# A private publisher may override the client's bundled community trust.
if [ -n "${NC_DBS_APPROVALS:-}${NC_DBS_APPROVALS_SHA256:-}" ]; then
if [ -z "${NC_DBS_APPROVALS:-}" ] || [ ! -f "$NC_DBS_APPROVALS" ] || [ -L "$NC_DBS_APPROVALS" ] || [ ! -r "$NC_DBS_APPROVALS" ]; then
    echo "[Netcap Service Mode] Set NC_DBS_APPROVALS to a readable regular operator registry file mounted read-only outside the database directory." >&2
    exit 1
fi
case "${NC_DBS_APPROVALS_SHA256:-}" in
    ''|*[!0-9a-f]*)
        echo "[Netcap Service Mode] Set NC_DBS_APPROVALS_SHA256 to the independently obtained lowercase SHA-256 registry pin." >&2
        exit 1 ;;
esac
if [ "${#NC_DBS_APPROVALS_SHA256}" -ne 64 ]; then
    echo "[Netcap Service Mode] NC_DBS_APPROVALS_SHA256 must contain 64 lowercase hexadecimal characters." >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    registry_digest=$(sha256sum < "$NC_DBS_APPROVALS")
elif command -v shasum >/dev/null 2>&1; then
    registry_digest=$(shasum -a 256 < "$NC_DBS_APPROVALS")
else
    echo "[Netcap Service Mode] Install sha256sum or shasum to verify the supplied registry pin." >&2
    exit 1
fi
if [ "${registry_digest%% *}" != "$NC_DBS_APPROVALS_SHA256" ]; then
    echo "[Netcap Service Mode] Approval registry digest mismatch; check the independently supplied NC_DBS_APPROVALS_SHA256." >&2
    exit 1
fi
fi

# Check if databases exist, if not download them
DBS_PATH="${NC_CONFIG_ROOT:-$HOME/.config/netcap}/dbs"

if [ ! -d "$DBS_PATH" ] || [ -z "$(ls -A "$DBS_PATH" 2>/dev/null)" ]; then
    echo "[Netcap Service Mode] Databases not found, downloading..."
    
    if net util -download-dbs; then
        echo "[Netcap Service Mode] Databases downloaded successfully"
    else
        echo "[Netcap Service Mode] Reviewed database download failed; check the registry/pin and database server before restarting." >&2
        exit 1
    fi
else
    echo "[Netcap Service Mode] Databases found at $DBS_PATH"
fi

# Ensure data directory exists
mkdir -p "${NC_DATA_DIR:-/data/netcap-service}"

echo "[Netcap Service Mode] Starting HTTP server on ${NC_HTTP:-0.0.0.0:7070}"
echo "[Netcap Service Mode] Data directory: ${NC_DATA_DIR:-/data/netcap-service}"
echo "[Netcap Service Mode] DPI enabled: ${NC_DPI:-true}"

# Start service mode using capture command with --service flag
exec net capture --service \
    -http "${NC_HTTP:-0.0.0.0:7070}" \
    -service-data-dir "${NC_DATA_DIR:-/data/netcap-service}" \
    -dpi="${NC_DPI:-true}" \
    -service-max-file-size "${NC_MAX_FILE_SIZE:-104857600}" \
    -service-max-per-hour "${NC_MAX_ANALYSIS_HOUR:-10}" \
    -service-expiry "${NC_SESSION_EXPIRY:-60}" \
    -service-cleanup "${NC_CLEANUP_INTERVAL:-10}"
