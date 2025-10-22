# Linux Build Integration via Docker - Summary

## Overview

The goreleaser configuration has been enhanced to automatically build Linux binaries using Docker, ensuring all platform artifacts are included in GitHub releases.

## What Was Added

### 1. Docker Build Environment (`Dockerfile.goreleaser`)
- Base: Go 1.21 on Debian Bookworm
- Includes all DPI libraries: nDPI, libtrace, libprotoident
- Pre-configured with goreleaser
- ~2GB Docker image (cached for fast rebuilds)

### 2. Build Script (`scripts/build-linux-docker.sh`)
- Automatically triggered by goreleaser `before` hooks
- Builds/caches Docker image
- Runs Linux build in container
- Merges artifacts into main `dist/` directory
- Graceful fallback if Docker unavailable

### 3. Linux-Specific Config (`.goreleaser-linux.yml`)
- Builds for Linux amd64 and arm64
- Both DPI-enabled and nodpi variants
- Outputs to `dist-linux/` directory

### 4. Integration (`before` hook in `.goreleaser.yml`)
```yaml
before:
  hooks:
  - bash scripts/build-linux-docker.sh
```

## Build Matrix

| Platform | Architecture | DPI Support | Config |
|----------|--------------|-------------|--------|
| macOS | arm64 | ✅ Yes | `.goreleaser.yml` |
| macOS | arm64 | ❌ No (nodpi) | `.goreleaser.yml` |
| Windows | amd64 | ❌ No (nodpi) | `.goreleaser.yml` |
| Linux | amd64 | ✅ Yes | `.goreleaser-linux.yml` (Docker) |
| Linux | arm64 | ✅ Yes | `.goreleaser-linux.yml` (Docker) |
| Linux | amd64 | ❌ No (nodpi) | `.goreleaser-linux.yml` (Docker) |
| Linux | arm64 | ❌ No (nodpi) | `.goreleaser-linux.yml` (Docker) |

## Usage

### Standard Release
```bash
# Single command builds ALL platforms
goreleaser release --snapshot --clean --skip-publish --skip-validate
```

### Skip Linux Builds
```bash
# Build only macOS/Windows (no Docker required)
SKIP_DOCKER_BUILD=1 goreleaser release --snapshot --clean --skip-publish --skip-validate
```

## Build Artifacts

After a successful build, `dist/` contains:

```
dist/
├── netcap_v0.X.X_darwin_arm64.tar.gz          # macOS with DPI
├── netcap_nodpi_v0.X.X_darwin_arm64.tar.gz    # macOS without DPI
├── netcap_nodpi_v0.X.X_windows_amd64.tar.gz   # Windows without DPI
├── netcap_v0.X.X_linux_amd64.tar.gz           # Linux amd64 with DPI
├── netcap_v0.X.X_linux_arm64.tar.gz           # Linux arm64 with DPI
├── netcap_nodpi_v0.X.X_linux_amd64.tar.gz     # Linux amd64 without DPI
├── netcap_nodpi_v0.X.X_linux_arm64.tar.gz     # Linux arm64 without DPI
├── checksums.txt                               # All checksums merged
└── artifacts.json                              # Metadata for GitHub release
```

## Benefits

1. **Single Command**: One goreleaser command builds all platforms
2. **Automated**: Linux build happens automatically via Docker
3. **CI/CD Ready**: Works in GitHub Actions or any CI with Docker
4. **Consistent**: All builds use same base configuration
5. **Cached**: Docker image cached for fast subsequent builds
6. **Graceful Degradation**: Falls back if Docker unavailable

## Requirements

- **Docker Desktop**: Must be installed and running
- **Disk Space**: ~2GB for Docker image
- **First Build**: ~10-15 minutes (compiling DPI libraries)
- **Subsequent Builds**: ~1-2 minutes (cached image)

## GitHub Actions Integration (Future)

The setup is ready for CI/CD:

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install dependencies
        run: |
          brew install goreleaser libpcap ndpi libprotoident libtrace
      
      - name: Run GoReleaser
        uses: goreleaser/goreleaser-action@v5
        with:
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Troubleshooting

### Docker Not Available
The build script automatically detects if Docker is unavailable and skips Linux builds with a warning:
```
==> Warning: Docker not found, skipping Linux builds
```

### Force Rebuild Docker Image
```bash
docker rmi netcap-builder:latest
rm .docker-build-timestamp
goreleaser release --snapshot --clean --skip-publish --skip-validate
```

### Debug Linux Build
```bash
# Enter Docker container
docker run --rm -it -v "$PWD":/workspace -w /workspace netcap-builder:latest bash

# Run build manually
goreleaser release --config .goreleaser-linux.yml --snapshot --clean
```

## Documentation

- **GORELEASER.md** - Complete build documentation
- **scripts/README.md** - Build script details
- **Dockerfile.goreleaser** - Docker environment setup

## Files Modified/Added

**Added:**
- `Dockerfile.goreleaser`
- `scripts/build-linux-docker.sh`
- `.goreleaser-linux.yml`
- `GORELEASER.md`
- `scripts/README.md`
- `.gitignore` (added `.docker-build-timestamp`)

**Modified:**
- `.goreleaser.yml` (added `before` hook, comments)

## Testing

Verify the integration:

```bash
# Test with Docker (builds all platforms)
goreleaser release --snapshot --clean --skip-publish --skip-validate

# Test without Docker (macOS/Windows only)
SKIP_DOCKER_BUILD=1 goreleaser release --snapshot --clean --skip-publish --skip-validate

# Verify artifacts
ls -lh dist/*.tar.gz
cat dist/checksums.txt

# Check binary architectures
file dist/netcap_darwin_arm64/net
file dist/netcap_linux_amd64_v1/net
file dist/netcap_linux_arm64/net
```

## Next Steps

1. **Test full build** with Docker to verify Linux artifacts
2. **Update CI/CD** if using GitHub Actions or similar
3. **Document** in main README.md if needed
4. **Tag and release** to test production workflow

## Notes

- Linux builds require Docker because cross-compiling with CGO from macOS to Linux is not feasible
- The Docker image is cached locally for performance
- All artifacts are automatically merged and ready for GitHub releases
- The build is backwards compatible - still works without Docker (just skips Linux)

