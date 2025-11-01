# Netcap Service Container with Local go-dpi

This directory contains the build configuration for the Netcap service container that uses a local version of the `dreadl0ck/go-dpi` library instead of the pinned version in `go.mod`.

## Purpose

This build variant is useful for:

- Testing changes to the go-dpi library before publishing
- Debugging DPI-related issues with unreleased go-dpi code
- Development workflows where go-dpi and netcap are being modified together

## Building

### Quick Start

From the netcap repository root:

```bash
# Build locally (assumes go-dpi is at ../go-dpi)
zeus build-service-local-dpi

# Build with custom go-dpi path
GO_DPI_PATH=/path/to/go-dpi zeus build-service-local-dpi

# Build and push to registry
NETCAP_PUSH_IMAGES=true zeus build-service-local-dpi
```

### Environment Variables

- `GO_DPI_PATH`: Path to local go-dpi directory (default: `../go-dpi`)
- `VERSION`: Image version tag (default: from zeus globals)
- `NETCAP_CONTAINER_REGISTRY`: Registry URL (default: `docker.io`)
- `NETCAP_CONTAINER_REGISTRY_USER`: Registry username (default: `dreadl0ck`)
- `NETCAP_PUSH_IMAGES`: Set to `true` to push after build
- `NETCAP_USE_BUILDX`: Use buildx for multi-platform (default: `true`)
- `NETCAP_PLATFORMS`: Target platforms (default: `linux/amd64,linux/arm64`)

## How It Works

The build script:

1. Verifies the local go-dpi directory exists
2. Generates a Dockerfile that:
   - Copies the local go-dpi directory into the build container at `/go-dpi`
   - Adds a replace directive to `go.mod`: `replace github.com/dreadl0ck/go-dpi => /go-dpi`
   - Builds netcap using the local go-dpi code
3. Creates a temporary build context containing both netcap and go-dpi
4. Builds and optionally pushes the container

## Differences from Standard build-service

- Image name: `netcap-service` (same as standard build, will overwrite)
- Uses local go-dpi via replace directive
- Dockerfile is generated dynamically by the build script
- Requires `GO_DPI_PATH` to point to a valid go-dpi directory

## Running

The container runs identically to the standard service container:

```bash
docker run -d -p 7070:7070 -v netcap-service-data:/data dreadl0ck/netcap-service:latest
```

Access the web UI at: http://localhost:7070

## Development Workflow

1. Make changes to go-dpi in your local directory
2. Build the container with local go-dpi:
   ```bash
   zeus build-service-local-dpi
   ```
3. Test the container locally
4. Once validated, publish go-dpi changes and update the version in netcap's go.mod
5. Use the standard `zeus build-service` for production releases

## Notes

- The Dockerfile in this directory is generated automatically by the build script
- The go-dpi version in the binary will be set to the git tag/commit from the local go-dpi directory
- This build uses the same image name as the standard build, so it will overwrite any existing `netcap-service` images
- This build is intended for development/testing, not production deployments

