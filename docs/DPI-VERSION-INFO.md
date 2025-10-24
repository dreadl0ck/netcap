# DPI Version Information Display

## Overview

NETCAP now displays DPI (Deep Packet Inspection) build information in the header output, showing whether DPI support is enabled and which versions of nDPI and libprotoident were used to build the binary.

## Implementation

### New Files

1. **`dpi/version.go`** - Contains version variables and functions for DPI-enabled builds
2. **`dpi/version_nodpi.go`** - Contains stub functions for no-DPI builds

### Modified Files

1. **`io/utils.go`** - Updated `FPrintBuildInfo()` to display DPI version information
2. **`docker/alpine/Dockerfile`** - Added DPI version ldflags
3. **`docker/ubuntu/Dockerfile`** - Added DPI version ldflags
4. **`docs/building-with-dpi.md`** - Added documentation on version information

## Output Examples

### Build WITHOUT DPI Support

```
                       / |
 _______    ______   _10 |_     _______   ______    ______
/     / \  /    / \ / 01/  |   /     / | /    / \  /    / \
0010100 /|/011010 /|101010/   /0101010/  001010  |/100110  |
01 |  00 |00    00 |  10 | __ 00 |       /    10 |00 |  01 |
10 |  01 |01001010/   00 |/  |01 \_____ /0101000 |00 |__10/|
10 |  00 |00/    / |  10  00/ 00/    / |00    00 |00/   00/
00/   10/  0101000/    0010/   0010010/  0010100/ 1010100/
                                                  00 |
Network Protocol Analysis Framework               00 |
created by Philipp Mieden, 2018                   00/
v0.7.2

> Date of execution: 2025-10-24 14:40:24.756414 +0000 UTC
> NETCAP build commit: eae0c928e0e8f0ef7cf5128c8ba2da0000f59c86
> go runtime version: go1.25.1
> number of cores: 10 cores
> DPI support disabled
> gopacket: github.com/gopacket/gopacket version: v1.4.0
```

### Build WITH DPI Support (Docker Build)

```
                       / |
 _______    ______   _10 |_     _______   ______    ______
/     / \  /    / \ / 01/  |   /     / | /    / \  /    / \
0010100 /|/011010 /|101010/   /0101010/  001010  |/100110  |
01 |  00 |00    00 |  10 | __ 00 |       /    10 |00 |  01 |
10 |  01 |01001010/   00 |/  |01 \_____ /0101000 |00 |__10/|
10 |  00 |00/    / |  10  00/ 00/    / |00    00 |00/   00/
00/   10/  0101000/    0010/   0010010/  0010100/ 1010100/
                                                  00 |
Network Protocol Analysis Framework               00 |
created by Philipp Mieden, 2018                   00/
v0.7.2

> Date of execution: 2025-10-24 14:40:24.756414 +0000 UTC
> NETCAP build commit: eae0c928e0e8f0ef7cf5128c8ba2da0000f59c86
> go runtime version: go1.25.1
> number of cores: 10 cores
> DPI support enabled (nDPI: 4.14.0, libprotoident: 2.0.15-1)
> gopacket: github.com/gopacket/gopacket version: v1.4.0
> go-dpi: github.com/dreadl0ck/go-dpi version: v1.2.0
```

### Build WITH DPI Support (Local Build, no version info set)

```
                       / |
 _______    ______   _10 |_     _______   ______    ______
/     / \  /    / \ / 01/  |   /     / | /    / \  /    / \
0010100 /|/011010 /|101010/   /0101010/  001010  |/100110  |
01 |  00 |00    00 |  10 | __ 00 |       /    10 |00 |  01 |
10 |  01 |01001010/   00 |/  |01 \_____ /0101000 |00 |__10/|
10 |  00 |00/    / |  10  00/ 00/    / |00    00 |00/   00/
00/   10/  0101000/    0010/   0010010/  0010100/ 1010100/
                                                  00 |
Network Protocol Analysis Framework               00 |
created by Philipp Mieden, 2018                   00/
v0.7.2

> Date of execution: 2025-10-24 14:40:24.756414 +0000 UTC
> NETCAP build commit: eae0c928e0e8f0ef7cf5128c8ba2da0000f59c86
> go runtime version: go1.25.1
> number of cores: 10 cores
> DPI support enabled (nDPI: runtime, libprotoident: runtime)
> gopacket: github.com/gopacket/gopacket version: v1.4.0
> go-dpi: github.com/dreadl0ck/go-dpi version: v1.2.0
```

## Build Configuration

### Automatic Version Detection

The `gen-version` command automatically extracts dependency versions from `go.mod` and updates the appropriate files:

```bash
# Run gen-version to update all version information
zeus gen-version
```

This command will:
1. Update the main `version.go` file with the project version and commit hash
2. Extract the gopacket version from `go.mod` and add it to `version.go`
3. Extract the go-dpi version from `go.mod` and update `dpi/version.go`

This ensures that the displayed versions always match the dependencies specified in `go.mod`.

### Docker Builds

Docker builds automatically include specific DPI library versions via ldflags:

```dockerfile
RUN GOOS=linux GOARCH=amd64 go build ${TAGS} \
  -ldflags "-s -w \
    -X github.com/dreadl0ck/netcap.Version=v${VERSION} \
    -X github.com/dreadl0ck/netcap/dpi.NDPIVersion=4.14.0 \
    -X github.com/dreadl0ck/netcap/dpi.LibprotoidentVersion=2.0.15-1" \
  -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd
```

### Local Builds

For local builds, you can optionally set DPI version information:

```bash
# Build with DPI version info
go build -ldflags "-s -w \
  -X github.com/dreadl0ck/netcap/dpi.NDPIVersion=4.14.0 \
  -X github.com/dreadl0ck/netcap/dpi.LibprotoidentVersion=2.0.15-1" \
  -o bin/net github.com/dreadl0ck/netcap/cmd
```

## Version Detection

To check your installed DPI library versions:

### macOS (Homebrew)
```bash
brew list --versions ndpi libprotoident
```

### Linux (Debian/Ubuntu)
```bash
dpkg -l | grep -E '(ndpi|protoident)'
```

### Linux (RedHat/CentOS)
```bash
rpm -qa | grep -E '(ndpi|protoident)'
```

### Using otool/ldd
```bash
# macOS
otool -L bin/net | grep -E '(ndpi|protoident)'

# Linux
ldd bin/net | grep -E '(ndpi|protoident)'
```

## Commands that Display Build Info

The build information (including DPI version) is displayed when running these commands:

- `net agent` (when executed, not with -h)
- `net label` (when executed)
- `net proxy` (when executed)
- `net collect` (when executed)
- `net capture` (in collector configuration output)
- Maltego transforms (in stderr)

## Technical Details

### Build Tags

The DPI version information uses Go build tags to compile different versions:

- **Without `nodpi` tag**: Includes `dpi/version.go` with actual DPI support
- **With `nodpi` tag**: Includes `dpi/version_nodpi.go` with stub functions

### API

```go
// Check if DPI is supported
if dpi.HasDPISupport() {
    // DPI is available
}

// Get version info string
info := dpi.GetVersionInfo()
// Returns: "DPI support enabled (nDPI: 4.14.0, libprotoident: 2.0.15-1)"
// or: "DPI support disabled"
```

### Variables

```go
// In dpi/version.go (DPI-enabled builds)
var (
    NDPIVersion = "unknown"              // Set via ldflags
    LibprotoidentVersion = "unknown"     // Set via ldflags
    GoDPIVersion = "v1.2.0"              // Default from go.mod
)
```

## See Also

- [Building with DPI Support](building-with-dpi.md)
- [Deep Packet Inspection Documentation](deep-packet-inspection.md)

