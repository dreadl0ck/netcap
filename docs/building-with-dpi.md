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

Check if your binary has DPI support:

```bash
otool -L bin/net | grep -E '(ndpi|protoident)'
```

Expected output:
```
/opt/homebrew/opt/ndpi/lib/libndpi.so.4.14.0
/opt/homebrew/opt/libprotoident/lib/libprotoident.2.dylib
```

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

## Building Without DPI

To explicitly build without DPI support:

```bash
zeus install-nodpi
```

Or manually:

```bash
go build -tags nodpi -ldflags "-s -w" -o bin/net github.com/dreadl0ck/netcap/cmd
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

