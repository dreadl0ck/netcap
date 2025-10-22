# Building and Pushing the Database Server Container

This document describes how to build and push the netcap database server container using the Zeus build system.

## Quick Start

### Build Locally

```bash
# Build container locally (no push)
zeus build-dbs-server
```

### Build and Push to Docker Hub

```bash
# Build and push to Docker Hub
NETCAP_PUSH_IMAGES=true zeus build-dbs-server
```

### Build and Push to Custom Registry

```bash
# Build and push to custom registry
NETCAP_CONTAINER_REGISTRY=registry.example.com \
NETCAP_CONTAINER_REGISTRY_USER=myorg \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server
```

## Environment Variables

### Registry Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `NETCAP_CONTAINER_REGISTRY` | Container registry URL | `docker.io` |
| `NETCAP_CONTAINER_REGISTRY_USER` | Registry username/organization | `dreadl0ck` |
| `NETCAP_PUSH_IMAGES` | Set to `true` to push after build | (not set) |
| `VERSION` | Image version tag | `0.6.11` (from zeus globals) |

### Image Name

The image name is hardcoded as: **`netcap-dbs-server`**

## Image Tag Format

The full image tag depends on the registry:

**Docker Hub:**
```
dreadl0ck/netcap-dbs-server:0.6.11
dreadl0ck/netcap-dbs-server:latest
```

**Custom Registry:**
```
registry.example.com/netcap-dbs-server:0.6.11
registry.example.com/netcap-dbs-server:latest
```

## Examples

### Example 1: Local Development Build

```bash
# Build for local testing only
zeus build-dbs-server

# Run locally
docker run -d -p 8080:8080 \
  -v netcap-dbs-data:/data \
  dreadl0ck/netcap-dbs-server:0.6.11
```

### Example 2: Docker Hub Release

```bash
# Login to Docker Hub
docker login

# Build and push with current version
NETCAP_PUSH_IMAGES=true zeus build-dbs-server

# Images pushed:
#   dreadl0ck/netcap-dbs-server:0.6.11
#   dreadl0ck/netcap-dbs-server:latest
```

### Example 3: GitHub Container Registry

```bash
# Login to GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Build and push
NETCAP_CONTAINER_REGISTRY=ghcr.io \
NETCAP_CONTAINER_REGISTRY_USER=dreadl0ck \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server

# Image: ghcr.io/dreadl0ck/netcap-dbs-server:0.6.11
```

### Example 4: Private Registry

```bash
# Login to private registry
docker login registry.company.com

# Build and push
NETCAP_CONTAINER_REGISTRY=registry.company.com \
NETCAP_CONTAINER_REGISTRY_USER=engineering \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server

# Image: registry.company.com/netcap-dbs-server:0.6.11
```

### Example 5: Custom Version Tag

```bash
# Build with custom version
VERSION=dev-$(git rev-parse --short HEAD) \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server

# Image: dreadl0ck/netcap-dbs-server:dev-a1b2c3d
```

### Example 6: AWS ECR

```bash
# Login to AWS ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com

# Build and push
NETCAP_CONTAINER_REGISTRY=123456789012.dkr.ecr.us-east-1.amazonaws.com \
NETCAP_CONTAINER_REGISTRY_USER="" \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server

# Image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/netcap-dbs-server:0.6.11
```

### Example 7: Azure Container Registry

```bash
# Login to Azure ACR
az acr login --name myregistry

# Build and push
NETCAP_CONTAINER_REGISTRY=myregistry.azurecr.io \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server

# Image: myregistry.azurecr.io/netcap-dbs-server:0.6.11
```

## Build Script Details

### What the Script Does

1. **Validates Configuration**: Checks environment variables and sets defaults
2. **Builds Image**: Runs `docker build` with proper context and Dockerfile
3. **Tests Container**: Starts container and performs health check
4. **Tags Image**: Creates version tag and 'latest' tag
5. **Pushes to Registry**: Optionally pushes both tags to configured registry

### Build Context

- **Dockerfile**: `docker/dbs-server/Dockerfile`
- **Build Context**: Project root (for access to all Go source)
- **Multi-stage**: Yes (builder + runtime stages)

### Build Arguments

The script passes the following build arguments:
- `VERSION`: Netcap version for metadata

### Health Check

After building, the script performs a health check:
1. Starts container on port 8080
2. Waits 5 seconds
3. Calls `http://localhost:8080/health`
4. Stops and removes test container

## Registry Authentication

### Docker Hub

```bash
docker login
# Enter username and password
```

### GitHub Container Registry

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
```

### Google Container Registry

```bash
gcloud auth configure-docker
```

### AWS ECR

```bash
aws ecr get-login-password --region REGION | \
  docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.REGION.amazonaws.com
```

### Azure Container Registry

```bash
az acr login --name REGISTRY_NAME
```

### Private Registry with Credentials

```bash
docker login registry.example.com -u USERNAME -p PASSWORD
```

## Troubleshooting

### Build Fails

```bash
# Check Docker is running
docker ps

# Clean Docker cache
docker system prune -a

# Rebuild without cache
docker build --no-cache -f docker/dbs-server/Dockerfile .
```

### Push Fails

```bash
# Verify you're logged in
docker login $REGISTRY

# Check credentials
cat ~/.docker/config.json

# Manual push
docker push dreadl0ck/netcap-dbs-server:0.6.11
```

### Health Check Fails

The health check may fail if:
- Container needs more time to initialize
- Port 8080 is already in use
- Network issues

This is a warning only and doesn't stop the build.

### Permission Denied

```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker

# Or run with sudo
sudo zeus build-dbs-server
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build and Push DBS Server

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Login to Docker Hub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
      
      - name: Install Zeus
        run: |
          curl -s https://zeus.pm/install.sh | bash
          echo "$HOME/.zeus/bin" >> $GITHUB_PATH
      
      - name: Build and Push
        env:
          NETCAP_PUSH_IMAGES: true
          VERSION: ${{ github.ref_name }}
        run: zeus build-dbs-server
```

### GitLab CI Example

```yaml
build-dbs-server:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - curl -s https://zeus.pm/install.sh | bash
    - export PATH="$HOME/.zeus/bin:$PATH"
    - export NETCAP_CONTAINER_REGISTRY=$CI_REGISTRY
    - export NETCAP_CONTAINER_REGISTRY_USER=$CI_PROJECT_NAMESPACE
    - export NETCAP_PUSH_IMAGES=true
    - zeus build-dbs-server
  only:
    - tags
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    environment {
        NETCAP_PUSH_IMAGES = 'true'
        NETCAP_CONTAINER_REGISTRY = 'registry.company.com'
    }
    stages {
        stage('Build and Push') {
            steps {
                sh 'zeus build-dbs-server'
            }
        }
    }
}
```

## Manual Build (Without Zeus)

If you don't have Zeus installed:

```bash
cd docker/dbs-server

# Build
docker build -t dreadl0ck/netcap-dbs-server:0.6.11 -f Dockerfile ../..

# Tag as latest
docker tag dreadl0ck/netcap-dbs-server:0.6.11 dreadl0ck/netcap-dbs-server:latest

# Push
docker push dreadl0ck/netcap-dbs-server:0.6.11
docker push dreadl0ck/netcap-dbs-server:latest
```

## See Also

- [Docker Deployment Guide](README.md)
- [Zeus Build System Documentation](../../zeus/README.md)
- [Database Server Implementation](../../dbs/SERVER_IMPLEMENTATION.md)

