# Builder Images Quick Start

## TL;DR

Speed up your Linux builds by 60-75% with pre-built base images.

## Quick Setup (2 steps)

### 1. Pull the qualified builders

```bash
cd /path/to/netcap
for variant in alpine alpine-dpi ubuntu ubuntu-dpi; do
  docker pull --platform linux/amd64 "$(python3 zeus/scripts/builder-image.py "$variant")"
done
```

To build new candidate builders instead:
```bash
BUILDER_VERSION="yara1.22.0-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d)-candidate1" zeus build-builder-images
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
BUILDER_VERSION="yara1.22.0-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d)-candidate2" PUSH=true ./zeus/scripts/build-builder-images.sh
```

Team members can then skip step 1 and just pull:
```bash
for variant in alpine alpine-dpi ubuntu ubuntu-dpi; do
  docker pull --platform linux/amd64 "$(python3 zeus/scripts/builder-image.py "$variant")"
done
```

## Verify It's Working

Verify anonymous registry availability and linux/amd64 manifest selection:
```bash
python3 zeus/scripts/builder-image.py --verify-public
```

The command prints four digest-qualified references from `images.lock.json`. These native images support linux/amd64 only; arm64 and multi-platform requests are rejected. Candidate publication never replaces existing tags or shared `latest` tags.

## When to Rebuild

Rebuild builder images when:
- ⚙️ Upgrading Go version
- 📦 Updating DPI libraries (nDPI, libtrace, etc.)
- 🔒 Applying security updates

Just run the build command again:
```bash
BUILDER_VERSION="yara1.22.0-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d)-candidate3" ./zeus/scripts/build-builder-images.sh
```

## Troubleshooting

### "Image not found" error

**Solution**: Build or pull the builder images first
```bash
# Option 1: Build a uniquely named candidate locally
BUILDER_VERSION="yara1.22.0-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d)-candidate4" ./zeus/scripts/build-builder-images.sh

# Option 2: Pull from registry
for variant in alpine alpine-dpi ubuntu ubuntu-dpi; do
  docker pull --platform linux/amd64 "$(python3 zeus/scripts/builder-image.py "$variant")"
done
```

### Build is still slow

**Solution**: Inspect the selected builder and build log before rebuilding
```bash
python3 zeus/scripts/builder-image.py --verify-public
docker image inspect "$(python3 zeus/scripts/builder-image.py alpine-dpi)"
```

## Need More Info?

- **Full documentation**: `docker/builders/README.md`
- **Implementation details**: `docker/builders/IMPLEMENTATION_SUMMARY.md`
- **Build script**: `zeus/scripts/build-builder-images.sh`

## Commands Reference

```bash
# Build all builder images locally
BUILDER_VERSION="yara1.22.0-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d)-candidate5" ./zeus/scripts/build-builder-images.sh

# Build and push to registry
BUILDER_VERSION="yara1.22.0-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d)-candidate6" PUSH=true ./zeus/scripts/build-builder-images.sh

# Use the full supported Docker Hub namespace
REGISTRY=docker.io/dreadl0ck BUILDER_VERSION="yara1.22.0-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d)-candidate7" PUSH=true ./zeus/scripts/build-builder-images.sh

# Build with version tag
BUILDER_VERSION="yara1.22.0-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d)-candidate8" ./zeus/scripts/build-builder-images.sh

# List builder images
docker images | grep netcap-builder

# Plan final artifact builds without building or publishing
python3 zeus/scripts/native-candidate.py --revision "$REVISION" --output .qualification/final-linux --plan
```

Signing, notarization, actual native-host execution and the Windows Npcap manual gate are documented in `README.md` under “Candidate artifact qualification.” Builder availability alone does not certify every release platform.

---

**Questions?** Check the full documentation in `docker/builders/README.md`
