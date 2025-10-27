#!/bin/sh
set -e

echo "[Netcap Try Service] Starting..."

# Check if databases exist, if not download them
DBS_PATH="$HOME/.config/netcap/dbs"

if [ ! -d "$DBS_PATH" ] || [ -z "$(ls -A $DBS_PATH 2>/dev/null)" ]; then
    echo "[Netcap Try Service] Databases not found, downloading..."
    
    # Try to download databases, but don't fail if it errors
    # (some databases might not be critical)
    if netcap util -download-dbs; then
        echo "[Netcap Try Service] Databases downloaded successfully"
    else
        echo "[Netcap Try Service] Warning: Database download failed or incomplete"
        echo "[Netcap Try Service] Service will continue, but some features may be limited"
    fi
else
    echo "[Netcap Try Service] Databases found at $DBS_PATH"
fi

# Ensure data directory exists
mkdir -p "${NC_DATA_DIR:-/data/netcap-try}"

echo "[Netcap Try Service] Starting HTTP server on ${NC_HTTP:-0.0.0.0:7070}"
echo "[Netcap Try Service] Data directory: ${NC_DATA_DIR:-/data/netcap-try}"
echo "[Netcap Try Service] DPI enabled: ${NC_DPI:-true}"

# Start the try service with DPI support
exec netcap try \
    -http "${NC_HTTP:-0.0.0.0:7070}" \
    -data-dir "${NC_DATA_DIR:-/data/netcap-try}" \
    -dpi="${NC_DPI:-true}" \
    -max-file-size "${NC_MAX_FILE_SIZE:-52428800}" \
    -max-analysis-hour "${NC_MAX_ANALYSIS_HOUR:-2}" \
    -session-expiry "${NC_SESSION_EXPIRY:-60}" \
    -cleanup-interval "${NC_CLEANUP_INTERVAL:-10}"

