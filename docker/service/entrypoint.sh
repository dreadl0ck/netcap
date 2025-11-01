#!/bin/sh
set -e

echo "[Netcap Service Mode] Starting..."

# Check if databases exist, if not download them
DBS_PATH="$HOME/.config/netcap/dbs"

if [ ! -d "$DBS_PATH" ] || [ -z "$(ls -A $DBS_PATH 2>/dev/null)" ]; then
    echo "[Netcap Service Mode] Databases not found, downloading..."
    
    # Try to download databases, but don't fail if it errors
    # (some databases might not be critical)
    if netcap util -download-dbs; then
        echo "[Netcap Service Mode] Databases downloaded successfully"
    else
        echo "[Netcap Service Mode] Warning: Database download failed or incomplete"
        echo "[Netcap Service Mode] Service will continue, but some features may be limited"
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
exec netcap capture --service \
    -http "${NC_HTTP:-0.0.0.0:7070}" \
    -service-data-dir "${NC_DATA_DIR:-/data/netcap-service}" \
    -dpi="${NC_DPI:-true}" \
    -service-max-file-size "${NC_MAX_FILE_SIZE:-104857600}" \
    -service-max-per-hour "${NC_MAX_ANALYSIS_HOUR:-10}" \
    -service-expiry "${NC_SESSION_EXPIRY:-60}" \
    -service-cleanup "${NC_CLEANUP_INTERVAL:-10}"

