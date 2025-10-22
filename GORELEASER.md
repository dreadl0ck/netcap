# GoReleaser Build Configuration

This project uses GoReleaser to build release binaries for multiple platforms.

## Build Configurations

### `.goreleaser.yml` - macOS/Windows Builds

Use this configuration on **macOS** (arm64) to build:

- **macOS arm64** with DPI support (libprotoident, libtrace, libndpi)
- **macOS arm64** without DPI (nodpi)
- **Windows amd64** without DPI (nodpi)

**Usage:**
```bash
goreleaser release --snapshot --clean --skip-publish --skip-validate
```

**Output:**
- `dist/netcap_v0.X.X_darwin_arm64.tar.gz` - macOS with DPI
- `dist/netcap_nodpi_v0.X.X_darwin_arm64.tar.gz` - macOS without DPI  
- `dist/netcap_nodpi_v0.X.X_windows_amd64.tar.gz` - Windows without DPI

### `.goreleaser-linux.yml` - Linux Builds

Use this configuration on **Linux** to build:

- **Linux amd64** with DPI support
- **Linux arm64** with DPI support
- **Linux amd64** without DPI (nodpi)
- **Linux arm64** without DPI (nodpi)

**Usage:**
```bash
goreleaser release --config .goreleaser-linux.yml --snapshot --clean --skip-publish --skip-validate
```

**Output:**
- `dist-linux/netcap_v0.X.X_linux_amd64.tar.gz` - Linux amd64 with DPI
- `dist-linux/netcap_v0.X.X_linux_arm64.tar.gz` - Linux arm64 with DPI
- `dist-linux/netcap_nodpi_v0.X.X_linux_amd64.tar.gz` - Linux amd64 without DPI
- `dist-linux/netcap_nodpi_v0.X.X_linux_arm64.tar.gz` - Linux arm64 without DPI

## Why Separate Configurations?

Cross-compiling with CGO (required for libpcap/gopacket and DPI libraries) from macOS to Linux is not supported without additional cross-compilation toolchains. To maintain simplicity and reliability:

1. **macOS builds** are done on macOS (currently only arm64 due to DPI library availability)
2. **Linux builds** should be done on Linux or via Docker
3. **Windows builds** can be done from macOS with mingw-w64 (nodpi only)

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

### macOS
```bash
brew install goreleaser
brew install libpcap
# For DPI builds:
brew install ndpi libprotoident libtrace
```

### Linux
```bash
# Install goreleaser (see https://goreleaser.com/install/)
# For DPI builds:
apt-get install libpcap-dev libndpi-dev  # Ubuntu/Debian
# or
yum install libpcap-devel  # CentOS/RHEL
```

## Docker Build (Alternative for Linux)

To build Linux binaries from macOS using Docker:

```bash
docker run --rm -v "$PWD":/workspace -w /workspace goreleaser/goreleaser:latest release --config .goreleaser-linux.yml --snapshot --clean --skip-publish --skip-validate
```

Note: You'll need to install DPI libraries in the Docker container for DPI-enabled builds.

## Release Process

1. **Tag the release:**
   ```bash
   git tag -a v0.X.X -m "Release v0.X.X"
   git push origin v0.X.X
   ```

2. **Build macOS/Windows:**
   ```bash
   goreleaser release --rm-dist
   ```

3. **Build Linux** (on Linux system):
   ```bash
   goreleaser release --config .goreleaser-linux.yml --rm-dist
   ```

4. **Upload all artifacts** to GitHub releases

## Troubleshooting

### Error: `undefined symbols for architecture x86_64`
- You're trying to build darwin/amd64 on an arm64 Mac
- Solution: Only build for arm64, or install x86_64 versions of DPI libraries

### Error: `call to undeclared function 'setresgid'`
- You're trying to cross-compile for Linux from macOS with CGO
- Solution: Use `.goreleaser-linux.yml` on a Linux system

### Error: `undefined: pcapErrorNotActivated`
- gopacket requires CGO, even with nodpi tags
- Solution: Ensure CGO_ENABLED=1 for all builds

