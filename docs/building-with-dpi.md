# Building Netcap with DPI Support

## Overview

Netcap supports Deep Packet Inspection (DPI) using:
- **nDPI** (v4.14 Stable) - for protocol detection (244+ applications)
- **libprotoident** (v2.x) - for protocol identification (500+ protocols)

## macOS

### Prerequisites

Install the required libraries via Homebrew:

```bash
brew install ndpi libprotoident
```

### Building

The `zeus install` command automatically detects if DPI libraries are installed:

```bash
zeus install
```

If the libraries are detected, it will build with DPI support. Otherwise, it builds without DPI (using the `nodpi` tag).

**Note:** go-dpi v1.1.0+ includes built-in CGO directives for Homebrew, so no manual configuration is needed. The package automatically handles both Intel (`/usr/local`) and Apple Silicon (`/opt/homebrew`) Mac installations.

### Verifying DPI Support

#### Check Linked Libraries

Check if your binary has DPI support by examining linked libraries:

```bash
# macOS
otool -L bin/net | grep -E '(ndpi|protoident)'

# Linux
ldd bin/net | grep -E '(ndpi|protoident)'
```

Expected output (macOS):
```
/opt/homebrew/opt/ndpi/lib/libndpi.so.4.14.0
/opt/homebrew/opt/libprotoident/lib/libprotoident.2.dylib
```

#### Check Version Information

NETCAP displays DPI version information when running any command:

```bash
./net capture -h
```

The header will show:
- For builds **with DPI**: `> DPI support enabled (nDPI: 4.14.0, libprotoident: 2.0.15-1)`
- For builds **without DPI**: `> DPI support disabled`
- For local builds with DPI: `> DPI support enabled (nDPI: unknown, libprotoident: unknown)`

**Note:** Docker builds include specific version information set at build time. Local builds will show "unknown" for versions but will still indicate whether DPI is enabled or disabled.

## Linux

### Prerequisites

Install nDPI and libprotoident from your package manager or build from source:

```bash
# Ubuntu/Debian
sudo apt-get install libndpi-dev libprotoident-dev

# Build from source
# nDPI: https://github.com/ntop/nDPI
# libprotoident: https://github.com/wanduow/libprotoident
```

### Building

```bash
zeus install-linux
```

## Matched YARA-X runtime

YARA-enabled builds pair `github.com/VirusTotal/yara-x/go v1.22.0` with the
C API pinned in `scripts/yara-x.env`. Install Rust `1.95.0` first, then build
into a dedicated prefix:

```sh
PREFIX="$PWD/.native/yara-x" sh scripts/build-yara-x.sh
YARA_X_PREFIX="$PWD/.native/yara-x" sh scripts/with-yara-x.sh go build -o bin/net ./cmd/net
otool -L bin/net # macOS: confirm the isolated libyara_x_capi.dylib
```

`with-yara-x.sh` keys CGO compilation on the library checksum: changing only
`PKG_CONFIG_PATH` can reuse cached linker flags for an older installation.
The generated `.pc` names the library absolutely so another dependency's `-L`
cannot select Homebrew's YARA-X. For macOS distribution, pass the same prefix
as `--yara-prefix` to `zeus/scripts/bundle-macos-runtime.py`.

Linux packaging requires `NETCAP_BUILDER_IMAGE` naming a builder produced from
the matching `docker/builders/*Dockerfile`; downstream images reject C APIs
other than `1.22.0`. Pass it as a build argument to Docker or an environment
variable to the `zeus/scripts/build-*.sh` wrappers. Qualification uses local
image names; publish and pin a qualified builder digest before a release.
`appstore,nodpi,noyara` excludes the YARA Go package and native library.

## Building Without DPI

To explicitly build without DPI support:

```bash
zeus install-nodpi
```

Or manually:

```bash
go build -tags nodpi -ldflags "-s -w" -o bin/net github.com/dreadl0ck/netcap/cmd/net
```

## Setting DPI Version Information

### Docker Builds

Docker builds automatically include specific DPI library versions in the build metadata:

```dockerfile
# These versions are set in the Dockerfile
-X github.com/dreadl0ck/netcap/internal/dpi.NDPIVersion=4.14.0
-X github.com/dreadl0ck/netcap/internal/dpi.LibprotoidentVersion=2.0.15-1
```

### Local Builds with Version Info

For local builds, you can optionally specify the DPI library versions:

```bash
# First, check your installed versions
# macOS
brew list --versions ndpi libprotoident

# Linux
dpkg -l | grep -E '(ndpi|protoident)'  # Debian/Ubuntu
rpm -qa | grep -E '(ndpi|protoident)'  # RedHat/CentOS

# Build with version information
go build -ldflags "-s -w \
  -X github.com/dreadl0ck/netcap/internal/dpi.NDPIVersion=4.14.0 \
  -X github.com/dreadl0ck/netcap/internal/dpi.LibprotoidentVersion=2.0.15-1" \
  -o bin/net github.com/dreadl0ck/netcap/cmd/net
```

## Compatibility

- **go-dpi**: v1.1.0+ (required for nDPI v4.x support)
- **nDPI**: v4.14 Stable (v3.x supported by go-dpi v1.0.x)
- **libprotoident**: v2.x

## Troubleshooting

### Header Files Not Found

If you get `fatal error: 'ndpi/ndpi_main.h' file not found`:

1. Ensure libraries are installed: `brew list ndpi libprotoident`
2. Verify go-dpi version is v1.1.0+: `go list -m github.com/dreadl0ck/go-dpi`
3. If using an older go-dpi version, upgrade it: `go get github.com/dreadl0ck/go-dpi@v1.1.0`

**Note:** With go-dpi v1.1.0+, you should NOT need to manually set CGO flags as the package handles this automatically. If you do set them manually, you'll get harmless "ignoring duplicate libraries" warnings.

### API Version Mismatch

If you encounter errors about undefined functions or struct members:

1. Check your nDPI version: `brew list --versions ndpi`
2. Upgrade go-dpi if needed: `go get github.com/dreadl0ck/go-dpi@latest`

### Runtime Library Errors

If the binary can't find libraries at runtime:

```bash
# macOS - add to ~/.zshrc or ~/.bash_profile
export DYLD_LIBRARY_PATH=/opt/homebrew/lib:$DYLD_LIBRARY_PATH

# Linux
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

## See Also

- [Deep Packet Inspection Documentation](deep-packet-inspection.md)
- [Device Profiles](device-profiles.md)
