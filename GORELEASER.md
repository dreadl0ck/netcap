# GoReleaser Build Configuration

This project uses GoReleaser to build release binaries for multiple platforms.

## Automated Build (Recommended)

### Single Command for All Platforms

The main `.goreleaser.yml` automatically builds for **all platforms** including Linux via Docker:

**Usage:**
```bash
goreleaser release --snapshot --clean --skip-publish --skip-validate
```

**What happens:**
1. Docker builds Linux binaries (amd64 + arm64, with and without DPI)
2. macOS/Windows binaries are built natively
3. All artifacts are merged into `dist/` directory
4. Ready for GitHub release

**Output:**
- `dist/netcap_v0.X.X_darwin_arm64.tar.gz` - macOS with DPI
- `dist/netcap_nodpi_v0.X.X_darwin_arm64.tar.gz` - macOS without DPI  
- `dist/netcap_nodpi_v0.X.X_windows_amd64.tar.gz` - Windows without DPI
- `dist/netcap_v0.X.X_linux_amd64.tar.gz` - Linux amd64 with DPI
- `dist/netcap_v0.X.X_linux_arm64.tar.gz` - Linux arm64 with DPI
- `dist/netcap_nodpi_v0.X.X_linux_amd64.tar.gz` - Linux amd64 without DPI
- `dist/netcap_nodpi_v0.X.X_linux_arm64.tar.gz` - Linux arm64 without DPI

**Requirements:**
- Docker must be installed and running
- First build will take longer (builds Docker image with DPI libraries)
- Subsequent builds are faster (uses cached Docker image)

## Manual Build (Advanced)

### `.goreleaser.yml` - macOS/Windows Only

Build without Docker (skips Linux):

```bash
# Disable the Docker hook temporarily
SKIP_DOCKER_BUILD=1 goreleaser release --snapshot --clean --skip-publish --skip-validate
```

### `.goreleaser-linux.yml` - Linux Builds Only

Use this configuration on **Linux** to build Linux binaries natively:

**Usage:**
```bash
goreleaser release --config .goreleaser-linux.yml --snapshot --clean --skip-publish --skip-validate
```

**Output:** (in `dist-linux/` directory)
- `netcap_v0.X.X_linux_amd64.tar.gz` - Linux amd64 with DPI
- `netcap_v0.X.X_linux_arm64.tar.gz` - Linux arm64 with DPI
- `netcap_nodpi_v0.X.X_linux_amd64.tar.gz` - Linux amd64 without DPI
- `netcap_nodpi_v0.X.X_linux_arm64.tar.gz` - Linux arm64 without DPI

## Build Architecture

Cross-compiling with CGO (required for libpcap/gopacket and DPI libraries) from macOS to Linux is not supported without Docker. Our solution:

1. **macOS builds** → Built natively on macOS arm64
2. **Linux builds** → Built in Docker container with DPI libraries (automated)
3. **Windows builds** → Cross-compiled from macOS (nodpi only)

The Docker integration (`scripts/build-linux-docker.sh`) is triggered automatically by goreleaser's `before` hooks, ensuring all artifacts are built and merged seamlessly.

## DPI vs No-DPI Builds

### With DPI (`netcap`)
- Includes Deep Packet Inspection libraries:
  - **nDPI** - Protocol detection
  - **libprotoident** - Protocol identification
  - **libtrace** - Packet capture
- Requires CGO and native C libraries
- Larger binary size (~54MB)
- Full protocol analysis capabilities

### Without DPI (`netcap_nodpi`)
- Uses `-tags=nodpi` build flag
- No DPI library dependencies
- Slightly smaller binary (~53MB)
- Basic packet capture and analysis

## Prerequisites

### For Automated Build (with Docker)
```bash
# macOS
brew install goreleaser docker
brew install libpcap ndpi libprotoident libtrace

# Ensure Docker is running
docker --version
```

### For Manual Native Builds

#### macOS
```bash
brew install goreleaser libpcap
# For DPI builds:
brew install ndpi libprotoident libtrace
```

#### Linux
```bash
# Install goreleaser (see https://goreleaser.com/install/)
# For DPI builds:
apt-get install libpcap-dev build-essential  # Ubuntu/Debian
# DPI libraries (nDPI, libtrace, libprotoident) must be compiled from source
```

## Docker Build Details

The automated Linux build uses `Dockerfile.goreleaser` which includes:
- Go 1.21 on Debian Bookworm
- libpcap, nDPI, libtrace, and libprotoident compiled from source
- goreleaser

The script `scripts/build-linux-docker.sh`:
1. Builds the Docker image (cached after first build)
2. Runs `.goreleaser-linux.yml` in the container
3. Copies artifacts from `dist-linux/` to `dist/`
4. Merges checksums for all platforms

## Release Process

1. **Ensure Docker is running:**
   ```bash
   docker ps
   ```

2. **Tag the release:**
   ```bash
   git tag -a v0.X.X -m "Release v0.X.X"
   git push origin v0.X.X
   ```

3. **Build and release all platforms:**
   ```bash
   # This builds macOS, Windows, AND Linux (via Docker)
   goreleaser release --clean
   ```

4. **Artifacts are automatically published** to GitHub releases

### For Testing (Snapshot Build)

```bash
# Test build without publishing
goreleaser release --snapshot --clean --skip-publish --skip-validate

# Check all artifacts
ls -lh dist/*.tar.gz
```

## Troubleshooting

### Docker Issues

#### Docker not found
```
==> Warning: Docker not found, skipping Linux builds
```
**Solution:** Install Docker Desktop for macOS

#### Docker not running
```
==> Warning: Docker is not running, skipping Linux builds
```
**Solution:** Start Docker Desktop

#### Skip Linux builds temporarily
```bash
SKIP_DOCKER_BUILD=1 goreleaser release --snapshot --clean --skip-publish --skip-validate
```

### Build Errors

#### Error: `undefined symbols for architecture x86_64`
- You're trying to build darwin/amd64 on an arm64 Mac
- **Solution:** Only build for arm64, or install x86_64 versions of DPI libraries

#### Error: `call to undeclared function 'setresgid'`
- You're trying to cross-compile for Linux from macOS with CGO
- **Solution:** The Docker integration should handle this automatically

#### Error: `undefined: pcapErrorNotActivated`
- gopacket requires CGO, even with nodpi tags
- **Solution:** Ensure CGO_ENABLED=1 for all builds

### Rebuilding Docker Image

If DPI libraries or Dockerfile are updated:
```bash
# Remove cached Docker image
docker rmi netcap-builder:latest
rm .docker-build-timestamp

# Next goreleaser run will rebuild the image
goreleaser release --snapshot --clean --skip-publish --skip-validate
```

### Checking Build Artifacts

```bash
# List all generated artifacts
ls -lh dist/*.tar.gz

# Verify checksums
cat dist/checksums.txt

# Check binary types
file dist/netcap_darwin_arm64/net
file dist/netcap_linux_amd64_v1/net
```

