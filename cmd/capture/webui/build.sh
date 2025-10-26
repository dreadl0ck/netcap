#!/bin/bash
#
# Build script for Netcap Web UI
# This script builds the Next.js frontend and can optionally rebuild the Go binary
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$SCRIPT_DIR/frontend"

echo "==> Building Netcap Web UI Frontend"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "Error: Node.js is not installed. Please install Node.js 18+ and try again."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "Error: npm is not installed. Please install npm and try again."
    exit 1
fi

# Navigate to frontend directory
cd "$FRONTEND_DIR"

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "==> Installing dependencies..."
    npm install
fi

# Build the frontend (Next.js 14+ automatically exports when output: 'export' is set)
echo "==> Building Next.js application..."
npm run build

# Check if build was successful
if [ -d "out" ] && [ -f "out/index.html" ]; then
    echo "==> Frontend build successful!"
    echo "    Output: $FRONTEND_DIR/out/"
else
    echo "Error: Frontend build failed"
    exit 1
fi

# If --with-go flag is provided, rebuild the Go binary
if [ "$1" = "--with-go" ]; then
    echo ""
    echo "==> Building Go binary with embedded frontend..."
    cd "$SCRIPT_DIR/../../.."
    go build -o bin/net ./cmd
    if [ $? -eq 0 ]; then
        echo "==> Go binary built successfully!"
        echo "    Binary: bin/net"
    else
        echo "Error: Go build failed"
        exit 1
    fi
fi

echo ""
echo "==> Build complete!"
echo ""
echo "To use the web UI, run:"
echo "  net capture -read traffic.pcap -out output -http localhost:8080"

