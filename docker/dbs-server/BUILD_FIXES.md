# Docker Build Fixes - Database Server

## Issues Fixed

### 1. Go Version Mismatch
**Problem:** `go.work` specified Go 1.23.0 but `go.mod` required Go 1.25.1

**Fix:**
- Updated `go.work` to use Go 1.25.1
- Updated `tests/helpers/go.mod` to Go 1.25.1

### 2. Tests/Helpers Module Dependency
**Problem:** Docker build failed because tests/helpers module couldn't be found

**Fix:**
- Added tests/helpers to go.work workspace
- Added replace directive in go.mod: `replace github.com/dreadl0ck/netcap/tests/helpers => ./tests/helpers`
- Updated .dockerignore to exclude tests but allow tests/helpers/go.mod
- Modified Dockerfile to copy tests/helpers/go.mod before go mod download

### 3. DPI Dependencies Not Needed
**Problem:** Database server doesn't need DPI (Deep Packet Inspection) features, but build was failing on DPI dependencies

**Fix:**
- Added `-tags nodpi` to the build command
- Kept libpcap dependencies (still needed by gopacket even with nodpi)
- Added libpcap to both builder and runtime stages

## Final Dockerfile Changes

**Builder Stage:**
```dockerfile
# Install build dependencies (minimal set for nodpi build)
RUN apk add --no-cache git gcc musl-dev

# Build with nodpi tag
RUN apk add --no-cache libpcap-dev linux-headers
RUN CGO_ENABLED=1 GOOS=linux go build -tags nodpi -a -installsuffix cgo -ldflags="-s -w" -o netcap ./cmd
```

**Runtime Stage:**
```dockerfile
# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    git \
    git-lfs \
    libpcap \
    && git lfs install
```

## Files Modified

1. `go.work` - Updated Go version to 1.25.1, added tests/helpers
2. `go.mod` - Added replace directive for tests/helpers
3. `tests/helpers/go.mod` - Updated Go version to 1.25.1
4. `.dockerignore` - Excluded tests but allowed tests/helpers/go.mod, removed go.work files
5. `docker/dbs-server/.dockerignore` - Added go.work exclusion
6. `docker/dbs-server/Dockerfile` - Added nodpi build tag, libpcap dependencies

## Build Verification

**Image Size:** ~75MB (Alpine-based, nodpi build)

**Test Commands:**
```bash
# Build
cd docker/dbs-server
docker build -t netcap-dbs-server:test -f Dockerfile ../..

# Test
docker run --rm netcap-dbs-server:test netcap --version
docker run --rm netcap-dbs-server:test net util -h
```

**Result:** ✅ All builds successful

## Benefits of nodpi Build

1. **Smaller Dependencies:** No nDPI library compilation needed
2. **Faster Builds:** Skips DPI feature compilation
3. **Appropriate for Use Case:** Database server doesn't analyze packets
4. **Simpler Build Process:** Fewer C dependencies to manage

## Zeus Command Integration

The zeus `build-dbs-server` command automatically uses this Dockerfile with all fixes applied:

```bash
# Build locally
zeus build-dbs-server

# Build and push
NETCAP_PUSH_IMAGES=true zeus build-dbs-server
```

## Notes

- The nodpi tag prevents DPI features but still requires libpcap for gopacket
- Tests are excluded from Docker builds (not needed in production)
- go.work file is excluded from Docker builds to prevent version conflicts
- Multi-stage build keeps final image small (runtime only has necessary dependencies)

