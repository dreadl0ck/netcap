#!/bin/bash

# Sync the webUI frontend from capture to try service
# This ensures the try service has the latest frontend build

SOURCE_DIR="cmd/capture/webui/frontend/out"
TARGET_DIR="cmd/try/webui/frontend"

echo "[INFO] Syncing webUI frontend from capture to try service..."

# Remove old frontend if it exists
if [ -d "$TARGET_DIR" ]; then
    rm -rf "$TARGET_DIR"
fi

# Create target directory
mkdir -p "$TARGET_DIR"

# Copy the frontend build
if [ -d "$SOURCE_DIR" ]; then
    cp -r "$SOURCE_DIR" "$TARGET_DIR/"
    echo "[INFO] Frontend synced successfully"
else
    echo "[WARN] Source frontend not found at $SOURCE_DIR"
    echo "[WARN] Build the frontend first: cd cmd/capture/webui/frontend && npm run build"
    exit 1
fi

