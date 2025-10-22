# Zeus Build Command for Database Server

## Overview

The `build-dbs-server` zeus command provides an automated way to build and push the Netcap database server container to any container registry.

## Command Syntax

```bash
zeus build-dbs-server
```

## Quick Reference

```bash
# Build locally (no push)
zeus build-dbs-server

# Build and push to Docker Hub
NETCAP_PUSH_IMAGES=true zeus build-dbs-server

# Build and push to custom registry
NETCAP_CONTAINER_REGISTRY=registry.example.com \
NETCAP_CONTAINER_REGISTRY_USER=myorg \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server
```

## Environment Variables

### Required for Push

| Variable | Description | Example |
|----------|-------------|---------|
| `NETCAP_PUSH_IMAGES` | Set to `true` to enable pushing | `true` |

### Optional Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `NETCAP_CONTAINER_REGISTRY` | Registry URL | `docker.io` |
| `NETCAP_CONTAINER_REGISTRY_USER` | Registry username/org | `dreadl0ck` |
| `VERSION` | Image version tag | `0.6.11` (from zeus globals) |

## Image Naming

**Image Name (Hardcoded):** `netcap-dbs-server`

**Full Tag Format:**
- Docker Hub: `{USER}/netcap-dbs-server:{VERSION}`
- Other Registries: `{REGISTRY}/netcap-dbs-server:{VERSION}`

**Example Tags:**
```
dreadl0ck/netcap-dbs-server:0.6.11
dreadl0ck/netcap-dbs-server:latest
registry.example.com/netcap-dbs-server:0.6.11
ghcr.io/dreadl0ck/netcap-dbs-server:0.6.11
```

## What the Command Does

1. **Configures Registry**
   - Reads environment variables
   - Sets defaults for Docker Hub
   - Constructs full image tag

2. **Builds Container**
   - Uses multi-stage Dockerfile
   - Builds from `docker/dbs-server/Dockerfile`
   - Tags with version and latest

3. **Tests Container**
   - Starts container on port 8080
   - Performs health check at `/health`
   - Stops and removes test container

4. **Pushes to Registry** (if `NETCAP_PUSH_IMAGES=true`)
   - Pushes version tag
   - Pushes latest tag
   - Verifies successful push

## Usage Examples

### Local Development

Build for local testing without pushing:

```bash
zeus build-dbs-server

# Image available locally:
# dreadl0ck/netcap-dbs-server:0.6.11
```

### Docker Hub Release

Push to Docker Hub (requires authentication):

```bash
# Login first
docker login

# Build and push
NETCAP_PUSH_IMAGES=true zeus build-dbs-server

# Result:
#   dreadl0ck/netcap-dbs-server:0.6.11 ✓
#   dreadl0ck/netcap-dbs-server:latest ✓
```

### GitHub Container Registry

Push to GitHub Container Registry:

```bash
# Login
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Build and push
NETCAP_CONTAINER_REGISTRY=ghcr.io \
NETCAP_CONTAINER_REGISTRY_USER=dreadl0ck \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server

# Result:
#   ghcr.io/dreadl0ck/netcap-dbs-server:0.6.11 ✓
#   ghcr.io/dreadl0ck/netcap-dbs-server:latest ✓
```

### Private Registry

Push to a private registry:

```bash
# Login
docker login registry.company.com

# Build and push
NETCAP_CONTAINER_REGISTRY=registry.company.com \
NETCAP_CONTAINER_REGISTRY_USER=engineering \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server

# Result:
#   registry.company.com/netcap-dbs-server:0.6.11 ✓
#   registry.company.com/netcap-dbs-server:latest ✓
```

### Custom Version Tag

Build with a custom version (e.g., development build):

```bash
VERSION=dev-$(date +%Y%m%d) \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server

# Result:
#   dreadl0ck/netcap-dbs-server:dev-20241021 ✓
#   dreadl0ck/netcap-dbs-server:latest ✓
```

### AWS ECR

Push to AWS Elastic Container Registry:

```bash
# Login to AWS ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com

# Build and push (no user prefix for ECR)
NETCAP_CONTAINER_REGISTRY=123456789012.dkr.ecr.us-east-1.amazonaws.com \
NETCAP_CONTAINER_REGISTRY_USER="" \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server

# Result:
#   123456789012.dkr.ecr.us-east-1.amazonaws.com/netcap-dbs-server:0.6.11 ✓
```

## Configuration Files

The zeus command uses configuration from:

1. **`zeus/commands.yml`** - Command definition
2. **`zeus/scripts/build-dbs-server.sh`** - Build script
3. **`docker/dbs-server/Dockerfile`** - Container definition

## Testing the Build

The build script includes automatic testing:

```bash
# The script automatically:
1. Builds the image
2. Starts container on port 8080
3. Waits 5 seconds for initialization
4. Calls http://localhost:8080/health
5. Stops and removes test container
6. Reports health check result
```

**Note:** Health check failure is a warning only and doesn't stop the build.

## Output Example

```
[INFO] Building netcap database server container
[INFO] Image: dreadl0ck/netcap-dbs-server:0.6.11
[INFO] Registry: docker.io
[INFO] Version: 0.6.11
[+] Building 45.3s (18/18) FINISHED
[INFO] Successfully built dreadl0ck/netcap-dbs-server:0.6.11
[INFO] Testing container health check...
[INFO] Container started: a1b2c3d4e5f6
[INFO] Waiting for container to be healthy...
[INFO] ✓ Health check passed
[INFO] Tagging as latest: dreadl0ck/netcap-dbs-server:latest
[INFO] Pushing container to registry: docker.io
[INFO] ✓ Successfully pushed dreadl0ck/netcap-dbs-server:0.6.11
[INFO] Pushing latest tag...
[INFO] ✓ Successfully pushed dreadl0ck/netcap-dbs-server:latest
[INFO] Container image details:
REPOSITORY                        TAG       SIZE      CREATED
dreadl0ck/netcap-dbs-server      0.6.11    52.3MB    2 minutes ago
[INFO] Done!

To run the container locally:
  docker run -d -p 8080:8080 -v netcap-dbs-data:/data dreadl0ck/netcap-dbs-server:0.6.11
```

## Integration with CI/CD

### Environment-Based Configuration

Set environment variables in your CI/CD system:

```bash
# GitHub Actions
env:
  NETCAP_CONTAINER_REGISTRY: ghcr.io
  NETCAP_CONTAINER_REGISTRY_USER: ${{ github.repository_owner }}
  NETCAP_PUSH_IMAGES: true
  VERSION: ${{ github.ref_name }}

# GitLab CI
variables:
  NETCAP_CONTAINER_REGISTRY: $CI_REGISTRY
  NETCAP_CONTAINER_REGISTRY_USER: $CI_PROJECT_NAMESPACE
  NETCAP_PUSH_IMAGES: "true"
  VERSION: $CI_COMMIT_TAG
```

### Pipeline Integration

```bash
# In your CI/CD pipeline:
- name: Build Database Server
  run: zeus build-dbs-server
```

See `BUILD.md` for complete CI/CD examples.

## Troubleshooting

### Command Not Found

```bash
# Install zeus
curl -s https://zeus.pm/install.sh | bash

# Or check if zeus is in PATH
which zeus
```

### Docker Not Running

```bash
# Start Docker
sudo systemctl start docker  # Linux
open -a Docker              # macOS
```

### Permission Denied

```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### Registry Authentication Failed

```bash
# Verify login
docker login $REGISTRY

# Check config
cat ~/.docker/config.json
```

### Health Check Fails

Health check failures are warnings only. The container may need more time to initialize. To skip the test:

```bash
# Edit zeus/scripts/build-dbs-server.sh and comment out health check section
```

### Port Already in Use

If port 8080 is in use during testing:

```bash
# Find and stop process using port 8080
lsof -ti:8080 | xargs kill -9

# Or modify script to use different port
```

## Comparison with Manual Build

**Zeus Command:**
```bash
NETCAP_PUSH_IMAGES=true zeus build-dbs-server
```

**Manual Equivalent:**
```bash
cd docker/dbs-server
docker build --build-arg VERSION=0.6.11 -t dreadl0ck/netcap-dbs-server:0.6.11 -f Dockerfile ../..
docker tag dreadl0ck/netcap-dbs-server:0.6.11 dreadl0ck/netcap-dbs-server:latest
docker run -d -p 8080:8080 dreadl0ck/netcap-dbs-server:0.6.11
sleep 5
curl http://localhost:8080/health
docker stop $(docker ps -q --filter ancestor=dreadl0ck/netcap-dbs-server:0.6.11)
docker rm $(docker ps -aq --filter ancestor=dreadl0ck/netcap-dbs-server:0.6.11)
docker push dreadl0ck/netcap-dbs-server:0.6.11
docker push dreadl0ck/netcap-dbs-server:latest
```

**Benefit:** The zeus command automates all these steps with proper error handling.

## Related Documentation

- [BUILD.md](BUILD.md) - Detailed build instructions and examples
- [README.md](README.md) - Container deployment and usage
- [../../dbs/SERVER_IMPLEMENTATION.md](../../dbs/SERVER_IMPLEMENTATION.md) - Server implementation details
- [../../zeus/commands.yml](../../zeus/commands.yml) - Zeus command definitions

## Support

For issues or questions:
- Check the [troubleshooting section](#troubleshooting)
- Review build logs for error details
- See full documentation in `BUILD.md`
- Report issues at https://github.com/dreadl0ck/netcap/issues

