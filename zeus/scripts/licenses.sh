#!/bin/bash

# License checker script for netcap
# Analyzes both frontend (npm) and backend (Go) dependencies for licenses

set -e

echo "=========================================="
echo "Netcap License Analysis"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track if any tools needed to be installed
INSTALLED_TOOLS=""

###########################################
# Frontend License Analysis (npm packages)
###########################################

echo "=========================================="
echo "Frontend Dependencies (npm/pnpm)"
echo "=========================================="
echo ""

FRONTEND_DIR="cmd/capture/webui/frontend"

if [ -d "$FRONTEND_DIR" ]; then
    cd "$FRONTEND_DIR"
    
    # Check if node_modules exists
    if [ ! -d "node_modules" ]; then
        echo "[INFO] Installing frontend dependencies..."
        pnpm install --silent
    fi
    
    echo "[INFO] Running license-checker..."
    echo ""
    
    # Run license-checker (install if needed)
    if ! npx --yes license-checker --summary 2>/dev/null; then
        echo -e "${RED}[ERROR] Failed to run license-checker${NC}"
    fi
    
    echo ""
    echo "--- Potentially Problematic Licenses ---"
    echo ""
    
    # Check for GPL, LGPL, AGPL, and other copyleft licenses
    PROBLEMATIC=$(npx --yes license-checker --json 2>/dev/null | grep -E '"licenses":\s*"(GPL|LGPL|AGPL|MPL|EPL|CPL|CDDL|OSL|SSPL|UNLICENSED)' || true)
    
    if [ -n "$PROBLEMATIC" ]; then
        echo -e "${YELLOW}Found packages with copyleft or problematic licenses:${NC}"
        npx --yes license-checker --json 2>/dev/null | grep -B2 -A5 '"GPL\|LGPL\|AGPL\|MPL\|UNLICENSED' || true
    else
        echo -e "${GREEN}No problematic licenses found in frontend dependencies.${NC}"
    fi
    
    cd - > /dev/null
else
    echo -e "${YELLOW}[WARN] Frontend directory not found: $FRONTEND_DIR${NC}"
fi

echo ""
echo ""

###########################################
# Backend License Analysis (Go modules)
###########################################

echo "=========================================="
echo "Backend Dependencies (Go modules)"
echo "=========================================="
echo ""

# Check if go-licenses is installed
if ! command -v go-licenses &> /dev/null; then
    echo "[INFO] Installing go-licenses..."
    go install github.com/google/go-licenses@latest
    INSTALLED_TOOLS="$INSTALLED_TOOLS go-licenses"
fi

echo "[INFO] Running go-licenses..."
echo ""

# Run go-licenses report
# Suppress warnings about non-Go code and empty versions
go-licenses report ./... 2>&1 | grep -v "^W" | sort -t',' -k3 || true

echo ""
echo "--- License Summary ---"
echo ""

# Count licenses by type
go-licenses report ./... 2>/dev/null | grep -v "^W" | cut -d',' -f3 | sort | uniq -c | sort -rn || true

echo ""
echo "--- Potentially Problematic Licenses ---"
echo ""

# Check for GPL, LGPL, AGPL, MPL and other copyleft licenses (excluding netcap itself)
PROBLEMATIC_GO=$(go-licenses report ./... 2>/dev/null | grep -v "dreadl0ck/netcap" | grep -E 'GPL|LGPL|AGPL|MPL|EPL|CPL|CDDL|OSL|SSPL' || true)

if [ -n "$PROBLEMATIC_GO" ]; then
    echo -e "${YELLOW}Found packages with copyleft licenses:${NC}"
    echo "$PROBLEMATIC_GO"
    echo ""
    echo "Note: MPL-2.0 is file-level copyleft and generally safe for commercial use."
    echo "      LGPL allows linking without requiring your code to be open source."
else
    echo -e "${GREEN}No problematic licenses found in Go dependencies (excluding netcap itself).${NC}"
fi

echo ""
echo "=========================================="
echo "License Analysis Complete"
echo "=========================================="

if [ -n "$INSTALLED_TOOLS" ]; then
    echo ""
    echo "[INFO] Installed tools during analysis:$INSTALLED_TOOLS"
fi

