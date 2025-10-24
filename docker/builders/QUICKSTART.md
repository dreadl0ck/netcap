# Builder Images Quick Start

## TL;DR

Speed up your Linux builds by 60-75% with pre-built base images.

## Quick Setup (2 steps)

### 1. Build the builder images (one-time, ~15 minutes)

```bash
cd /path/to/netcap
./zeus/scripts/build-builder-images.sh
```

Or using zeus:
```bash
zeus build-builder-images
```

### 2. Build netcap as usual

```bash
# Your existing build commands now run faster!
zeus build-linux
```

**That's it!** Your builds will now be 10-15 minutes faster.

## What Just Happened?

Before, each build would:
1. ❌ Install Go (~1 min)
2. ❌ Install build tools (~2 min)
3. ❌ Install DPI libraries (~8 min)
4. ✅ Compile netcap (~3-5 min)
**Total: 15-20 minutes**

Now, each build:
1. ✅ Use cached builder image (instant)
2. ✅ Compile netcap (~3-5 min)
**Total: 3-5 minutes**

## Share with Team (Optional)

Push builder images to registry so your team can use them:

```bash
# Login to Docker Hub
docker login

# Build and push
PUSH=true ./zeus/scripts/build-builder-images.sh
```

Team members can then skip step 1 and just pull:
```bash
docker pull dreadl0ck/netcap-builder:alpine-latest
docker pull dreadl0ck/netcap-builder:alpine-dpi-latest
docker pull dreadl0ck/netcap-builder:ubuntu-latest
docker pull dreadl0ck/netcap-builder:ubuntu-dpi-latest
```

## Verify It's Working

Check that builder images exist:
```bash
docker images | grep netcap-builder
```

You should see:
```
dreadl0ck/netcap-builder   alpine-dpi-latest   ...   
dreadl0ck/netcap-builder   alpine-latest       ...   
dreadl0ck/netcap-builder   ubuntu-dpi-latest   ...   
dreadl0ck/netcap-builder   ubuntu-latest       ...   
```

## When to Rebuild

Rebuild builder images when:
- ⚙️ Upgrading Go version
- 📦 Updating DPI libraries (nDPI, libtrace, etc.)
- 🔒 Applying security updates

Just run the build command again:
```bash
./zeus/scripts/build-builder-images.sh
```

## Troubleshooting

### "Image not found" error

**Solution**: Build or pull the builder images first
```bash
# Option 1: Build locally
./zeus/scripts/build-builder-images.sh

# Option 2: Pull from registry
docker pull dreadl0ck/netcap-builder:alpine-latest
docker pull dreadl0ck/netcap-builder:alpine-dpi-latest
docker pull dreadl0ck/netcap-builder:ubuntu-latest
docker pull dreadl0ck/netcap-builder:ubuntu-dpi-latest
```

### Build is still slow

**Solution**: Clear Docker cache and rebuild
```bash
docker builder prune -a
./zeus/scripts/build-builder-images.sh
```

## Need More Info?

- **Full documentation**: `docker/builders/README.md`
- **Implementation details**: `docker/builders/IMPLEMENTATION_SUMMARY.md`
- **Build script**: `zeus/scripts/build-builder-images.sh`

## Commands Reference

```bash
# Build all builder images locally
./zeus/scripts/build-builder-images.sh

# Build and push to registry
PUSH=true ./zeus/scripts/build-builder-images.sh

# Use custom registry
REGISTRY=your-registry PUSH=true ./zeus/scripts/build-builder-images.sh

# Build with version tag
VERSION=v0.7.0 ./zeus/scripts/build-builder-images.sh

# List builder images
docker images | grep netcap-builder

# Remove old builder images
docker rmi dreadl0ck/netcap-builder:alpine-latest
docker rmi dreadl0ck/netcap-builder:alpine-dpi-latest
docker rmi dreadl0ck/netcap-builder:ubuntu-latest
docker rmi dreadl0ck/netcap-builder:ubuntu-dpi-latest
```

---

**Questions?** Check the full documentation in `docker/builders/README.md`

