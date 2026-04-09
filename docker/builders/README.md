# Netcap Builder Images

This directory contains base builder Docker images that are used to accelerate the Linux build process for netcap. These images contain all the necessary build dependencies and can be reused across multiple builds, significantly reducing build times.

## Builder Images

### 1. alpine-builder
- **Image**: `dreadl0ck/netcap-builder:alpine-latest`
- **Base**: `golang:1.25.1-alpine`
- **Purpose**: Builds musl-based Linux binaries without DPI support
- **Contains**: Go toolchain, gcc, libpcap, and basic build tools

### 2. alpine-dpi-builder
- **Image**: `dreadl0ck/netcap-builder:alpine-dpi-latest`
- **Base**: `golang:1.25.1-alpine`
- **Purpose**: Builds musl-based Linux binaries with DPI support
- **Contains**: All from alpine-builder plus:
  - nDPI (4.14)
  - libtrace (4.0.17-1)
  - libprotoident (2.0.15-1)
  - libflowmanager (3.0.0)
  - wandio (4.2.3-1)

### 3. ubuntu-builder
- **Image**: `dreadl0ck/netcap-builder:ubuntu-latest`
- **Base**: `ubuntu:18.04`
- **Purpose**: Builds glibc-based Linux binaries without DPI support
- **Contains**: Go 1.25.1, gcc, libpcap, and basic build tools

### 4. ubuntu-dpi-builder
- **Image**: `dreadl0ck/netcap-builder:ubuntu-dpi-latest`
- **Base**: `ubuntu:18.04`
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
./zeus/scripts/build-builder-images.sh
```

### Build and Push to Registry

To build and push to Docker Hub:

```bash
cd /path/to/netcap
PUSH=true ./zeus/scripts/build-builder-images.sh
```

### Build with Custom Registry

To use a different registry:

```bash
cd /path/to/netcap
REGISTRY=your-registry PUSH=true ./zeus/scripts/build-builder-images.sh
```

### Build Specific Versions

To build with version tags:

```bash
cd /path/to/netcap
VERSION=v0.7.0 PUSH=true ./zeus/scripts/build-builder-images.sh
```

## Using the Builder Images

The builder images are automatically referenced in the Dockerfiles located in:
- `docker/alpine/Dockerfile` - uses `alpine-dpi-builder`
- `docker/alpine-nodpi/Dockerfile` - uses `alpine-builder`
- `docker/ubuntu/Dockerfile` - uses `ubuntu-dpi-builder`
- `docker/ubuntu-nodpi/Dockerfile` - uses `ubuntu-builder`

No changes are needed to use them - just ensure the builder images exist either:
1. Pulled from Docker Hub: `docker pull dreadl0ck/netcap-builder:alpine-latest`
2. Built locally using the script above

## Maintenance

### When to Rebuild

You should rebuild the builder images when:
1. Go version is updated
2. DPI library versions change (nDPI, libtrace, etc.)
3. Build dependencies change
4. System package updates are needed

### Update Process

1. Update the relevant `Dockerfile` in this directory
2. Build the images: `./zeus/scripts/build-builder-images.sh`
3. Test with a full build: `NODPI=false VERSION=v0.7.0 zeus/scripts/build-alpine-docker.sh`
4. Push to registry: `PUSH=true ./zeus/scripts/build-builder-images.sh`

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
# Pull from registry
docker pull dreadl0ck/netcap-builder:alpine-latest
docker pull dreadl0ck/netcap-builder:alpine-dpi-latest
docker pull dreadl0ck/netcap-builder:ubuntu-latest
docker pull dreadl0ck/netcap-builder:ubuntu-dpi-latest

# Or build locally
./zeus/scripts/build-builder-images.sh
```

### Build Failures

If builds fail after updating builder images:

1. Clear Docker build cache: `docker builder prune -a`
2. Rebuild builder images: `./zeus/scripts/build-builder-images.sh`
3. Try again with clean cache: `ARGS="--no-cache" NODPI=false VERSION=v0.7.0 zeus/scripts/build-alpine-docker.sh`

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
3. Versioned to match your release tags

Example CI step:
```yaml
- name: Pull builder images
  run: |
    docker pull dreadl0ck/netcap-builder:alpine-latest
    docker pull dreadl0ck/netcap-builder:alpine-dpi-latest
    docker pull dreadl0ck/netcap-builder:ubuntu-latest
    docker pull dreadl0ck/netcap-builder:ubuntu-dpi-latest
```

