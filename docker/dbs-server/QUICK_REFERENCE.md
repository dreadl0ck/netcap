# Quick Reference - Database Server Build Command

## One-Line Commands

```bash
# Build locally
zeus build-dbs-server

# Build and push to Docker Hub
NETCAP_PUSH_IMAGES=true zeus build-dbs-server

# Build and push to custom registry
NETCAP_CONTAINER_REGISTRY=registry.example.com NETCAP_PUSH_IMAGES=true zeus build-dbs-server
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `NETCAP_CONTAINER_REGISTRY` | `docker.io` | Registry URL |
| `NETCAP_CONTAINER_REGISTRY_USER` | `dreadl0ck` | Username/Org |
| `NETCAP_PUSH_IMAGES` | (unset) | Set to `true` to push |
| `VERSION` | `0.6.11` | Image version |

## Image Names

```
# Docker Hub
dreadl0ck/netcap-dbs-server:0.6.11
dreadl0ck/netcap-dbs-server:latest

# Custom Registry
registry.example.com/netcap-dbs-server:0.6.11
registry.example.com/netcap-dbs-server:latest
```

## Common Registries

```bash
# Docker Hub (default)
NETCAP_PUSH_IMAGES=true zeus build-dbs-server

# GitHub Container Registry
NETCAP_CONTAINER_REGISTRY=ghcr.io \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server

# AWS ECR
NETCAP_CONTAINER_REGISTRY=123456789012.dkr.ecr.us-east-1.amazonaws.com \
NETCAP_CONTAINER_REGISTRY_USER="" \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server

# Azure ACR
NETCAP_CONTAINER_REGISTRY=myregistry.azurecr.io \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server

# Google GCR
NETCAP_CONTAINER_REGISTRY=gcr.io \
NETCAP_CONTAINER_REGISTRY_USER=my-project \
NETCAP_PUSH_IMAGES=true \
zeus build-dbs-server
```

## Pre-requisites

```bash
# Login to registry first
docker login                              # Docker Hub
docker login ghcr.io                      # GitHub
docker login registry.example.com        # Private
```

## Full Documentation

- **BUILD.md** - Complete build guide with examples
- **ZEUS_COMMAND.md** - Command reference and usage
- **README.md** - Deployment and usage guide
- **SETUP_SUMMARY.md** - Implementation overview

