# Netcap Builder Images

This directory contains base builder Docker images that are used to accelerate the Linux build process for netcap. These images contain all the necessary build dependencies and can be reused across multiple builds, significantly reducing build times.

## Builder Images

### 1. alpine-builder
- **Image**: `images.lock.json` → `alpine` (linux/amd64, YARA-X 1.22.0)
- **Base**: Go 1.27, Alpine 3.24.4
- **Purpose**: Builds musl-based Linux binaries without DPI support
- **Contains**: Go toolchain, gcc, libpcap, and basic build tools

### 2. alpine-dpi-builder
- **Image**: `images.lock.json` → `alpine-dpi` (linux/amd64, YARA-X 1.22.0)
- **Base**: Go 1.27, Alpine 3.24.4
- **Purpose**: Builds musl-based Linux binaries with DPI support
- **Contains**: All from alpine-builder plus:
  - nDPI (4.14)
  - libtrace (4.0.17-1)
  - libprotoident (2.0.15-1)
  - libflowmanager (3.0.0)
  - wandio (4.2.3-1)

### 3. ubuntu-builder
- **Image**: `images.lock.json` → `ubuntu` (linux/amd64, YARA-X 1.22.0)
- **Base**: `ubuntu:26.04`
- **Purpose**: Builds glibc-based Linux binaries without DPI support
- **Contains**: Go 1.27, gcc, libpcap, YARA-X 1.22.0, and basic build tools

### 4. ubuntu-dpi-builder
- **Image**: `images.lock.json` → `ubuntu-dpi` (linux/amd64, YARA-X 1.22.0)
- **Base**: `ubuntu:26.04`
- **Purpose**: Builds glibc-based Linux binaries with DPI support
- **Contains**: All from ubuntu-builder plus:
  - nDPI (4.14)
  - libtrace4 (from cloudsmith)
  - libprotoident (from cloudsmith)
  - libflowmanager (from cloudsmith)

## Building the Builder Images

### Build Locally

To build all builder images locally:

```bash
cd /path/to/netcap
BUILDER_VERSION="yara1.22.0-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d)-candidate1" ./zeus/scripts/build-builder-images.sh
```

### Build and Push to Registry

To build and push to Docker Hub:

```bash
cd /path/to/netcap
BUILDER_VERSION="yara1.22.0-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d)-candidate1" PUSH=true ./zeus/scripts/build-builder-images.sh
```

### Build with Custom Registry

The candidate publisher checks uniqueness in Docker Hub's `dreadl0ck` namespace. Its accepted `REGISTRY` values are `dreadl0ck` and `docker.io/dreadl0ck`:

```bash
cd /path/to/netcap
REGISTRY=docker.io/dreadl0ck BUILDER_VERSION="yara1.22.0-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d)-candidate2" PUSH=true ./zeus/scripts/build-builder-images.sh
```

### Build Specific Versions

To build with version tags:

```bash
cd /path/to/netcap
BUILDER_VERSION="yara1.22.0-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d)-candidate3" PUSH=true ./zeus/scripts/build-builder-images.sh
```

## Using the Builder Images

The builder images are automatically referenced in the Dockerfiles located in:
- `docker/alpine/Dockerfile` - uses `alpine-dpi-builder`
- `docker/alpine-nodpi/Dockerfile` - uses `alpine-builder`
- `docker/ubuntu/Dockerfile` - uses `ubuntu-dpi-builder`
- `docker/ubuntu-nodpi/Dockerfile` - uses `ubuntu-builder`

Runtime Dockerfiles and packaging scripts select the digest references in `images.lock.json`. Check availability with `python3 zeus/scripts/builder-image.py --verify-public`; pull one with `docker pull --platform linux/amd64 "$(python3 zeus/scripts/builder-image.py alpine-dpi)"`. An arm64 or multi-platform request is rejected by the native candidate tooling.

## Maintenance

### When to Rebuild

You should rebuild the builder images when:
1. Go version is updated
2. DPI library versions change (nDPI, libtrace, etc.)
3. Build dependencies change
4. System package updates are needed

### Update Process

1. Update the relevant `Dockerfile` in this directory
2. Build with a new `BUILDER_VERSION` candidate identifier as above.
3. Test with a full build: `NODPI=false VERSION=v0.7.0 zeus/scripts/build-alpine-docker.sh`
4. Publish the new candidate, qualify it, then update `images.lock.json` and runtime defaults together. Existing tags and shared `latest` tags are never replaced by the candidate publisher.

## Benefits

### Speed Improvements

Using builder images provides significant speedups:

- **Before**: Each build installs all dependencies from scratch (~10-20 minutes)
- **After**: Dependencies are pre-installed, only source code is compiled (~2-5 minutes)

### Consistency

- All builds use the same base environment
- Eliminates "works on my machine" issues
- Reproducible builds across different systems

### Disk Space

- Builder images are built once and reused
- Docker layer caching works more effectively
- No need to rebuild dependencies for each build variant

## Architecture

```
┌─────────────────────────────────────┐
│   Builder Base Images (cached)      │
│                                     │
│  ┌─────────────┬────────────────┐  │
│  │   Alpine    │    Ubuntu      │  │
│  │   Builders  │    Builders    │  │
│  │             │                │  │
│  │ ┌─────┬─────┴─┬────┬────────┤  │
│  │ │ DPI │ noDPI │ DPI│ noDPI  │  │
│  │ └─────┴───────┴────┴────────┘  │
│  │                                │  │
└──┴────────────────────────────────┴──┘
           │
           │ Used by
           ▼
┌──────────────────────────────────────┐
│   Build Process                      │
│   (copy source + compile only)       │
│                                      │
│   Output: netcap binaries            │
└──────────────────────────────────────┘
```

## Troubleshooting

### Image Not Found

If you get "image not found" errors:

```bash
for variant in alpine alpine-dpi ubuntu ubuntu-dpi; do
  docker pull --platform linux/amd64 "$(python3 zeus/scripts/builder-image.py "$variant")"
done
```

### Build Failures

If builds fail after updating builder images:

1. Verify the selected digest with `python3 zeus/scripts/builder-image.py --verify-public`.
2. Check the build log and `pkg-config --exact-version=1.22.0 yara_x_capi` inside that builder.
3. Build a new uniquely named candidate when native inputs change; cache pruning is not a packaging prerequisite.

### Library Version Mismatches

If you get library version errors:
1. Check the versions in the builder Dockerfiles
2. Update to match your requirements
3. Rebuild and push the builder images
4. Rebuild your netcap images

## CI/CD Integration

For continuous integration, ensure builder images are:
1. Pre-built and pushed to your registry
2. Pulled at the start of your CI pipeline
3. Selected by the qualified digests in `images.lock.json`

Example CI step:
```yaml
- name: Pull builder images
  run: |
    for variant in alpine alpine-dpi ubuntu ubuntu-dpi; do
      docker pull --platform linux/amd64 "$(python3 zeus/scripts/builder-image.py "$variant")"
    done
```

## Candidate artifact qualification

Use the coordinator's full 40-character commit in a clean checkout. Build its real frontend first (`pnpm install --frozen-lockfile && pnpm build` in `cmd/capture/webui/frontend`). These commands create local artifacts and receipts; they publish no release or runtime image:

Vite's deletion of the tracked `frontend/dist/MODULE_PLACEHOLDER.txt` is allowed by the source guard; other tracked changes and untracked source files are rejected.

```bash
python3 zeus/scripts/native-candidate.py --revision "$REVISION" --output .qualification/final-linux --plan
python3 zeus/scripts/native-candidate.py --revision "$REVISION" --output .qualification/final-linux
python3 zeus/scripts/qualify-native-host.py .qualification/final-linux/candidate.json \
  --host root@amsterdam-technologies.com --output .qualification/final-linux-native
```

`native-candidate.py` selects all four matched builders, stamps the source commit, bundles each ELF closure, and bounds its isolated BuildKit container to 2 CPUs. The native host worker compares transferred image configs/layers and archive hashes before exercising the packaged launcher. Only its own temporary directory and containers are removed; Docker caches and host configuration are not changed. Read `../server/README.md` before using the estate host.

Use Python 3.12+ on macOS with Xcode command-line tools. Build the approved source using the isolated YARA-X prefix from `scripts/build-yara-x.sh`, then sign its relocated archive:

```bash
python3 zeus/scripts/macos-candidate.py build --revision "$REVISION" --variant nodpi \
  --yara-prefix "$YARA_X_PREFIX" --output .qualification/final-macos-nodpi
python3 zeus/scripts/macos-candidate.py validate /path/to/extracted --min-os 15.0
python3 zeus/scripts/macos-candidate.py sign /path/to/candidate.tar.gz \
  --output .qualification/signed-candidate --min-os 15.0 --source-revision "$REVISION" \
  --identity "Developer ID Application: Amsterdam Technologies B.V. (NH3NGRWCB9)" \
  --team-id NH3NGRWCB9 --notarize
```

| Input | Required evidence |
| --- | --- |
| macOS no-DPI | arm64; binary minimum 15.0; every bundled library minimum ≤15.0 |
| macOS DPI | arm64; binary minimum 26.0; every bundled library minimum ≤26.0; pass `--min-os 26.0` |
| Signing | Same Developer ID team for executable/libraries, secure timestamps, hardened runtime, relocated dependency closure and matching inventory hashes |
| Notary authentication | `--keychain-profile NAME`, `NOTARY_KEYCHAIN_PROFILE`, or inherited `AC_USERNAME`/`AC_PASSWORD`; password is sent on stdin, never in command arguments or receipts |
| Native YARA | Signed HTTP-PCAP extraction and positive/negative scans must pass before ZIP submission |
| Clean-host runtime | Run `qualify-packaged-client.py /extracted/net --output /new/evidence --require-bpf --require-yara --source-revision "$REVISION"` on actual macOS 15/26 hosts as applicable |

Wasmtime requires `allow-unsigned-executable-memory` for this YARA-X build: `allow-jit` alone produced `SIGKILL`, `CODESIGNING: Invalid Page` during scanning. The signing script grants both to the CLI; it keeps library validation enabled. CLI ZIPs/Mach-O files cannot be stapled. Retain the Accepted notary receipt and per-file ticket log; raw `spctl --type execute` may report “valid but does not seem to be an app.” Notary acceptance does not certify execution on an older or clean host.

### Windows Npcap manual gate

Use a native Windows x64 machine with Python 3.12+, the final `net.exe`, an installed/licensed Npcap driver and an elevated console. No provided script installs or changes the driver. In the first PowerShell console:

```powershell
$env:NC_CONFIG_ROOT="$env:TEMP\netcap-npcap-config"
.\net.exe capture -iface '\Device\NPF_Loopback' -bpf 'udp dst port 19999' -include UDP -workers 2 -payload -json -compress=false -dpi=false -geoDB=false -network-detection=false -http= -out "$env:TEMP\netcap-npcap-live"
```

In a second console, send both controls, then stop the capture with Ctrl+C in the first:

```powershell
$udp = [System.Net.Sockets.UdpClient]::new()
$positive = [Text.Encoding]::ASCII.GetBytes('NETCAP_NPCAP_POSITIVE')
$negative = [Text.Encoding]::ASCII.GetBytes('NETCAP_NPCAP_NEGATIVE')
$udp.Send($positive,$positive.Length,'127.0.0.1',19999)
$udp.Send($negative,$negative.Length,'127.0.0.1',19998)
$udp.Dispose()
python zeus/scripts/qualify-windows-npcap.py .\net.exe --source-revision $REVISION --live-audit "$env:TEMP\netcap-npcap-live" --output "$env:TEMP\netcap-npcap-receipt"
```

The gate requires driver/service availability, interface enumeration, offline BPF controls, the live loopback marker and exclusion of port 19998. Missing host/driver/live evidence exits 3 with `state: blocked`; cross-compiled and driver-free CI binaries do not satisfy this gate.
