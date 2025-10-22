# Database Server Zeus Command - Setup Summary

## What Was Implemented

A complete Zeus build system integration for the Netcap database server container, enabling automated building and pushing to any container registry.

## Files Created

### 1. Build Script
- **Location:** `zeus/scripts/build-dbs-server.sh`
- **Purpose:** Handles Docker build, test, and push operations
- **Features:**
  - Multi-registry support (Docker Hub, GHCR, AWS ECR, Azure ACR, etc.)
  - Automatic health checking
  - Version and latest tag management
  - Comprehensive error handling and logging

### 2. Zeus Command Configuration
- **Location:** `zeus/commands.yml` (updated)
- **Command:** `build-dbs-server`
- **Features:**
  - Integrated help documentation
  - Environment variable configuration
  - Usage examples in help text

### 3. Documentation

#### BUILD.md
- Complete build and push guide
- Registry-specific examples (Docker Hub, GHCR, AWS ECR, Azure ACR, etc.)
- CI/CD integration examples (GitHub Actions, GitLab CI, Jenkins)
- Troubleshooting guide

#### ZEUS_COMMAND.md
- Zeus command reference
- Environment variable documentation
- Quick reference guide
- Output examples

#### README.md (updated)
- Added Zeus build instructions
- Added pre-built image pull instructions
- Updated quick start section

## Usage

### Basic Build (Local)

```bash
zeus build-dbs-server
```

**Result:** Image built locally as `dreadl0ck/netcap-dbs-server:0.6.11`

### Build and Push to Docker Hub

```bash
docker login
NETCAP_PUSH_IMAGES=true zeus build-dbs-server
```

**Result:** Images pushed:
- `dreadl0ck/netcap-dbs-server:0.6.11`
- `dreadl0ck/netcap-dbs-server:latest`

### Build and Push to Custom Registry

```bash
docker login registry.example.com
NETCAP_CONTAINER_REGISTRY=registry.example.com \
NETCAP_CONTAINER_REGISTRY_USER=myorg \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server
```

**Result:** Images pushed:
- `registry.example.com/netcap-dbs-server:0.6.11`
- `registry.example.com/netcap-dbs-server:latest`

## Configuration

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `NETCAP_CONTAINER_REGISTRY` | Registry URL | `docker.io` |
| `NETCAP_CONTAINER_REGISTRY_USER` | Registry username | `dreadl0ck` |
| `NETCAP_PUSH_IMAGES` | Enable push (true/false) | (not set) |
| `VERSION` | Image version tag | `0.6.11` |

### Image Naming

- **Image Name:** `netcap-dbs-server` (hardcoded)
- **Tag Format:** `{REGISTRY}/{USER}/netcap-dbs-server:{VERSION}`
- **Always Tagged:** Version tag + `latest` tag

## Features

### Automated Testing

The build script automatically:
1. Builds the container image
2. Starts the container on port 8080
3. Waits for initialization
4. Performs health check via `/health` endpoint
5. Stops and removes test container
6. Reports results

### Multi-Registry Support

Works with any container registry:
- ✅ Docker Hub
- ✅ GitHub Container Registry (ghcr.io)
- ✅ AWS Elastic Container Registry (ECR)
- ✅ Azure Container Registry (ACR)
- ✅ Google Container Registry (GCR)
- ✅ Private registries

### Error Handling

- Build failures stop execution
- Push failures provide login instructions
- Health check failures are warnings only
- All errors logged with clear messages

### Logging

Comprehensive logging throughout:
```
[INFO] Building netcap database server container
[INFO] Image: dreadl0ck/netcap-dbs-server:0.6.11
[INFO] Registry: docker.io
[INFO] Version: 0.6.11
...
[INFO] ✓ Health check passed
[INFO] ✓ Successfully pushed
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Build and Push DBS Server
  env:
    NETCAP_PUSH_IMAGES: true
    NETCAP_CONTAINER_REGISTRY: ghcr.io
  run: zeus build-dbs-server
```

### GitLab CI

```yaml
build-dbs:
  script:
    - export NETCAP_PUSH_IMAGES=true
    - zeus build-dbs-server
```

### Jenkins

```groovy
environment {
    NETCAP_PUSH_IMAGES = 'true'
}
stages {
    stage('Build') {
        steps {
            sh 'zeus build-dbs-server'
        }
    }
}
```

## Testing the Setup

### Verify Zeus Command

```bash
# Check command is registered
zeus build-dbs-server

# Should show build output
```

### Test Local Build

```bash
# Build without push
zeus build-dbs-server

# Verify image exists
docker images | grep netcap-dbs-server

# Test run
docker run -d -p 8080:8080 dreadl0ck/netcap-dbs-server:0.6.11

# Test health endpoint
curl http://localhost:8080/health
```

### Test Registry Push

```bash
# Login to registry
docker login

# Build and push
NETCAP_PUSH_IMAGES=true zeus build-dbs-server

# Verify pushed
docker pull dreadl0ck/netcap-dbs-server:0.6.11
```

## Architecture

```
zeus build-dbs-server
    ├─ Read environment variables
    ├─ Configure registry and tags
    ├─ Execute docker build
    │   ├─ Multi-stage build
    │   ├─ Alpine base image
    │   └─ Go compilation
    ├─ Test container
    │   ├─ Start on port 8080
    │   ├─ Health check
    │   └─ Stop and remove
    ├─ Tag images
    │   ├─ Version tag
    │   └─ Latest tag
    └─ Push to registry (if enabled)
        ├─ Push version
        └─ Push latest
```

## Benefits

1. **Automated Process**: Single command builds, tests, and pushes
2. **Multi-Registry**: Works with any container registry
3. **Version Management**: Automatic version and latest tagging
4. **Testing**: Built-in health checks
5. **Documentation**: Comprehensive docs for all use cases
6. **CI/CD Ready**: Easy integration with any CI/CD system
7. **Error Handling**: Clear error messages and recovery instructions
8. **Flexibility**: Environment-based configuration

## Related Files

```
docker/dbs-server/
├── Dockerfile              # Container definition
├── docker-compose.yml      # Compose deployment
├── README.md              # General documentation
├── BUILD.md               # Detailed build guide
├── ZEUS_COMMAND.md        # Zeus command reference
├── SETUP_SUMMARY.md       # This file
└── build.sh               # Direct build script (alternative)

zeus/
├── commands.yml           # Zeus command definitions
└── scripts/
    └── build-dbs-server.sh # Build script
```

## Next Steps

### For Users

1. **Local Testing:**
   ```bash
   zeus build-dbs-server
   docker run -p 8080:8080 dreadl0ck/netcap-dbs-server:0.6.11
   ```

2. **Push to Registry:**
   ```bash
   docker login
   NETCAP_PUSH_IMAGES=true zeus build-dbs-server
   ```

3. **Production Deployment:**
   ```bash
   cd docker/dbs-server
   docker-compose up -d
   ```

### For CI/CD

1. Configure environment variables
2. Add zeus command to pipeline
3. Set up registry authentication
4. Monitor build logs

### For Development

1. Modify `zeus/scripts/build-dbs-server.sh` for custom needs
2. Update `zeus/commands.yml` for new options
3. Test changes with local builds
4. Document changes in BUILD.md

## Support

- **Documentation:** See BUILD.md and ZEUS_COMMAND.md
- **Issues:** https://github.com/dreadl0ck/netcap/issues
- **CI/CD Examples:** BUILD.md has examples for all major platforms
- **Troubleshooting:** Both BUILD.md and ZEUS_COMMAND.md have troubleshooting sections

## Summary

The zeus `build-dbs-server` command provides a complete, automated solution for building and deploying the Netcap database server container. It supports any container registry, includes automated testing, and integrates seamlessly with CI/CD pipelines.

**Key Command:**
```bash
NETCAP_PUSH_IMAGES=true zeus build-dbs-server
```

**Key Environment Variables:**
- `NETCAP_CONTAINER_REGISTRY` - Registry URL
- `NETCAP_CONTAINER_REGISTRY_USER` - Username
- `NETCAP_PUSH_IMAGES` - Enable push

**Image Name:** `netcap-dbs-server` (hardcoded)

