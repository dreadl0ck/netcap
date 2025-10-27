#!/bin/bash
#
# Pack netcap databases into a versioned tarball with metadata
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Pack netcap databases into a versioned tarball with metadata and latest symlinks.

Options:
    -d, --dbs-dir PATH      Path to databases directory (default: ~/.config/netcap/dbs)
    -o, --output-dir PATH   Output directory for tarball (default: current directory)
    -v, --version DATE      Version string (default: current date YYYY-MM-DD)
    -s, --start-year YEAR   NVD start year for metadata (default: 2002)
    -D, --deploy BOOL       Deploy to remote server via scp (default: true)
    -h, --help              Show this help message

Examples:
    # Pack databases from default location (with deployment)
    zeus pack-dbs-tarball

    # Pack without deployment
    zeus pack-dbs-tarball -D false

    # Pack from custom directory with custom output
    zeus pack-dbs-tarball -d ./netcap-dbs -o ./release

    # Pack with custom version and custom deployment target
    DBS_DEPLOY_USER=admin DBS_DEPLOY_HOST=myserver.com zeus pack-dbs-tarball -v 2024-01-15

Environment Variables:
    NC_CONFIG_ROOT          Override default databases location if -d not specified
    DBS_VERSION             Default version if -v not specified (format: YYYY-MM-DD)
    DBS_DEPLOY_USER         Remote server user for deployment (default: root)
    DBS_DEPLOY_HOST         Remote server hostname for deployment (default: netcap.io)
    DBS_DEPLOY_PATH         Remote server path for deployment (default: /mnt/storage/netcap-dbs-server)

EOF
}

# Parse command line arguments
DBS_DIR=""
OUTPUT_DIR="."
VERSION="${DBS_VERSION:-$(date +%Y-%m-%d)}"
NVD_START_YEAR="${NVD_START_YEAR:-2002}"
DEPLOY="true"
DEPLOY_USER="${DBS_DEPLOY_USER:-root}"
DEPLOY_HOST="${DBS_DEPLOY_HOST:-netcap.io}"
DEPLOY_PATH="${DBS_DEPLOY_PATH:-/mnt/storage/netcap-dbs-server}"

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--dbs-dir)
            DBS_DIR="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -s|--start-year)
            NVD_START_YEAR="$2"
            shift 2
            ;;
        -D|--deploy)
            DEPLOY="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# If DBS_DIR not specified, try NC_CONFIG_ROOT, then default
if [[ -z "$DBS_DIR" ]]; then
    if [[ -n "$NC_CONFIG_ROOT" ]]; then
        DBS_DIR="$NC_CONFIG_ROOT/dbs"
        info "Using NC_CONFIG_ROOT: $DBS_DIR"
    else
        DBS_DIR="$HOME/.config/netcap/dbs"
        info "Using default location: $DBS_DIR"
    fi
fi

# Validate databases directory exists
if [[ ! -d "$DBS_DIR" ]]; then
    error "Databases directory does not exist: $DBS_DIR"
    exit 1
fi

# Check if directory has any database files
if [[ -z "$(ls -A "$DBS_DIR" 2>/dev/null)" ]]; then
    error "Databases directory is empty: $DBS_DIR"
    exit 1
fi

# Validate version format (YYYY-MM-DD)
if ! [[ "$VERSION" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    error "Invalid version format: $VERSION (expected YYYY-MM-DD)"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Resolve absolute paths
DBS_DIR=$(cd "$DBS_DIR" && pwd)
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)

info "Packing netcap databases"
info "Source:  $DBS_DIR"
info "Output:  $OUTPUT_DIR"
info "Version: $VERSION"

# Define output files
TARBALL_FILE="$OUTPUT_DIR/${VERSION}.tar.gz"
METADATA_FILE="$OUTPUT_DIR/${VERSION}.json"
LATEST_TARBALL="$OUTPUT_DIR/latest.tar.gz"
LATEST_METADATA="$OUTPUT_DIR/latest.json"

# Count database files
FILE_COUNT=$(find "$DBS_DIR" -type f | wc -l | tr -d ' ')
info "Found $FILE_COUNT files to pack"

# Create tarball
info "Creating tarball: ${VERSION}.tar.gz"
START_TIME=$(date +%s)

# Create tarball from the parent directory to preserve relative paths
PARENT_DIR=$(dirname "$DBS_DIR")
DBS_NAME=$(basename "$DBS_DIR")

cd "$PARENT_DIR"
tar -czf "$TARBALL_FILE" "$DBS_NAME"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Get tarball size
TARBALL_SIZE=$(du -h "$TARBALL_FILE" | cut -f1)

info "Tarball created in ${DURATION}s (${TARBALL_SIZE})"

# Create metadata JSON
info "Creating metadata: ${VERSION}.json"

cat > "$METADATA_FILE" << EOF
{
  "version": "${VERSION}",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tarball": "${VERSION}.tar.gz",
  "tarball_size_bytes": $(stat -f%z "$TARBALL_FILE" 2>/dev/null || stat -c%s "$TARBALL_FILE" 2>/dev/null || echo 0),
  "file_count": ${FILE_COUNT},
  "nvd_start_year": ${NVD_START_YEAR},
  "source": "pack-dbs script"
}
EOF

info "Metadata created"

# Create or update latest symlinks
info "Creating latest symlinks"

cd "$OUTPUT_DIR"

# Remove existing symlinks/files if they exist
rm -f "$LATEST_TARBALL" "$LATEST_METADATA"

# Try to create symlinks
if ln -s "${VERSION}.tar.gz" "$LATEST_TARBALL" 2>/dev/null; then
    info "Created symlink: latest.tar.gz -> ${VERSION}.tar.gz"
else
    # Symlink failed, copy instead
    warn "Symlinks not supported, copying files instead"
    cp "$TARBALL_FILE" "$LATEST_TARBALL"
    info "Copied: latest.tar.gz"
fi

if ln -s "${VERSION}.json" "$LATEST_METADATA" 2>/dev/null; then
    info "Created symlink: latest.json -> ${VERSION}.json"
else
    # Symlink failed, copy instead
    cp "$METADATA_FILE" "$LATEST_METADATA"
    info "Copied: latest.json"
fi

# Deploy to remote server if enabled
DEPLOYMENT_SUCCESS=false
if [[ "$DEPLOY" == "true" ]] || [[ "$DEPLOY" == "1" ]] || [[ "$DEPLOY" == "yes" ]]; then
    echo ""
    info "Deploying to remote server"
    info "Target: ${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_PATH}"
    
    # Check if scp is available
    if ! command -v scp &> /dev/null; then
        error "scp command not found, skipping deployment"
    else
        # Deploy the files
        if scp -r "${VERSION}.json" "${VERSION}.tar.gz" "latest.json" "latest.tar.gz" "${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_PATH}/dbs"; then
            info "✓ Deployment successful!"
            DEPLOYMENT_SUCCESS=true
        else
            error "Deployment failed"
            warn "You can manually deploy with:"
            echo "  scp -r ${VERSION}.json ${VERSION}.tar.gz latest.json latest.tar.gz ${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_PATH}/"
        fi
    fi
fi

# Clean up local files after successful deployment
if [[ "$DEPLOYMENT_SUCCESS" == "true" ]]; then
    echo ""
    info "Cleaning up local files after successful deployment"
    
    cd "$OUTPUT_DIR"
    rm -f "${VERSION}.json" "${VERSION}.tar.gz" "latest.json" "latest.tar.gz"
    
    info "✓ Local files removed"
fi

# Display summary
echo ""
info "✓ Pack complete!"
echo ""

if [[ "$DEPLOYMENT_SUCCESS" == "true" ]]; then
    echo "Files deployed to ${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_PATH}/dbs and removed locally:"
    echo "  ${VERSION}.tar.gz"
    echo "  ${VERSION}.json"
    echo "  latest.tar.gz"
    echo "  latest.json"
else
    echo "Output files:"
    echo "  ${TARBALL_FILE}"
    echo "  ${METADATA_FILE}"
    echo "  ${LATEST_TARBALL}"
    echo "  ${LATEST_METADATA}"
fi
echo ""
echo "Package details:"
echo "  Version:        ${VERSION}"
echo "  Size:           ${TARBALL_SIZE}"
echo "  Files:          ${FILE_COUNT}"
echo "  NVD Start Year: ${NVD_START_YEAR}"
echo "  Deploy:         ${DEPLOY}"
if [[ "$DEPLOY" == "true" ]] || [[ "$DEPLOY" == "1" ]] || [[ "$DEPLOY" == "yes" ]]; then
    echo "  Deploy Target:  ${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_PATH}"
    if [[ "$DEPLOYMENT_SUCCESS" == "true" ]]; then
        echo "  Local Cleanup:  ✓ Completed"
    else
        echo "  Local Cleanup:  Skipped (deployment failed)"
    fi
fi
echo ""

# Show usage examples only if files are still local
if [[ "$DEPLOYMENT_SUCCESS" != "true" ]]; then
    echo "To use this package with dbs-server:"
    echo ""
    echo "  # Copy to server directory"
    echo "  cp ${VERSION}.* /path/to/netcap-dbs-server/dbs/"
    echo ""
    echo "  # Or mount with Docker"
    echo "  docker run -d -p 8080:8080 \\"
    echo "    -v ${OUTPUT_DIR}:/data/netcap-dbs-server/dbs \\"
    echo "    dreadl0ck/netcap-dbs-server:latest"
    echo ""
fi

