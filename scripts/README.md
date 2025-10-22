# Build Scripts

## build-linux-docker.sh

Automated script to build Linux binaries using Docker. This script is automatically called by goreleaser's `before` hooks.

### What it does:

1. **Checks prerequisites:**
   - Verifies Docker is installed
   - Verifies Docker is running
   - Exits gracefully if Docker is unavailable (with warnings)

2. **Builds Docker image (if needed):**
   - Uses `Dockerfile.goreleaser` to create build environment
   - Includes Go 1.21, libpcap, nDPI, libtrace, and libprotoident
   - Caches the image for faster subsequent builds

3. **Runs Linux build:**
   - Executes `.goreleaser-linux.yml` inside Docker container
   - Builds Linux amd64 and arm64 binaries (with and without DPI)
   - Outputs to `dist-linux/` directory

4. **Merges artifacts:**
   - Copies Linux tar.gz files to `dist/` directory
   - Appends Linux checksums to main `dist/checksums.txt`

### Environment Variables:

- `SKIP_DOCKER_BUILD=1` - Skip Linux Docker build entirely

### Usage:

```bash
# Automatically called by goreleaser
goreleaser release --snapshot --clean --skip-publish --skip-validate

# Run manually
bash scripts/build-linux-docker.sh

# Skip Docker build
SKIP_DOCKER_BUILD=1 goreleaser release --snapshot --clean --skip-publish --skip-validate
```

### Requirements:

- Docker Desktop installed and running
- ~2GB disk space for Docker image
- First build: ~10-15 minutes (compiling DPI libraries)
- Subsequent builds: ~5 seconds (cached image)

### Troubleshooting:

**Docker image build fails:**
```bash
# Clear cache and rebuild
docker rmi netcap-builder:latest
rm .docker-build-timestamp
```

**Linux build fails:**
```bash
# Check Docker logs
docker logs $(docker ps -lq)

# Run build manually for debugging
docker run --rm -it -v "$PWD":/workspace -w /workspace netcap-builder:latest bash
```

**Clean up everything:**
```bash
# Remove Docker image
docker rmi netcap-builder:latest

# Remove artifacts
rm -rf dist-linux dist .docker-build-timestamp
```

