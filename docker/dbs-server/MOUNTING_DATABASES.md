# Mounting Pre-existing Databases in DBS Server

This document explains how the dbs-server handles database storage and how to mount pre-existing databases from the host.

## Storage Structure

The dbs-server stores databases in the following directory structure:

```
/data/netcap-dbs-server/          # Root directory (NC_CONFIG_ROOT)
├── dbs/                           # Database storage directory
│   ├── 2024-01-15.tar.gz         # Versioned database tarball
│   ├── 2024-01-15.json           # Metadata for version
│   ├── latest.tar.gz             # Symlink to latest version
│   └── latest.json               # Symlink to latest metadata
└── build/                         # Temporary build directory
```

## Configuration

The storage location is controlled by the `NC_CONFIG_ROOT` environment variable:

- **Default (standalone)**: `netcap-dbs-server/` (relative to working directory)
- **Default (Docker)**: `/data/netcap-dbs-server/`
- **Custom**: Set via `NC_CONFIG_ROOT` environment variable

## Permissions (Bind Mounts)

> **IMPORTANT** — When using a **bind mount** (host path → container path), the
> host directory must be writable by the user the container runs as. Otherwise
> the nightly database rebuild will fail with errors like:
>
> ```
> Scheduled rebuild failed: failed to create versioned directory:
>   mkdir /data/netcap-dbs-server/dbs/2026-04-23: permission denied
> ```

### Container User

The official image creates and runs as a non-root user:

- **User:** `netcap`
- **UID / GID:** `1000` / `1000`

This is set in `docker/dbs-server/Dockerfile`. The `chown` step in the Dockerfile
only applies when Docker initializes a **named volume** for the first time — it
has no effect on bind mounts, because the bind mount overlays the image path
with the host directory's existing ownership.

### Fix for Bind Mounts

On the host, set ownership to UID/GID 1000 before starting the container:

```bash
sudo chown -R 1000:1000 /path/on/host/netcap-dbs-server
sudo chmod -R u+rwX,g+rwX /path/on/host/netcap-dbs-server
```

If your host already has a `netcap` user with a different UID, either:

- Use the numeric UID/GID 1000 explicitly (as above), or
- Run the container as your host user via `--user "$(id -u):$(id -g)"` and
  ensure the host directory is owned by that user.

### Pre-flight Writability Check

The server now performs a writability probe at startup against both the
`build/` and `dbs/` directories. If either is not writable, startup **fails
fast** with a message including the running uid/gid and a hint:

```
dbs directory not writable: cannot write to /data/netcap-dbs-server/dbs
  (running as uid=1000 gid=1000): open ...: permission denied;
  if this is a bind-mounted host directory, ensure it is owned by the
  container user (e.g. `sudo chown -R 1000:1000 <hostdir>` for the default
  netcap user)
```

This prevents the previous failure mode where the container appeared healthy
and only failed at midnight during the scheduled rebuild.

### Named Volumes

Named Docker volumes (`-v netcap-dbs-data:/data`) do **not** require manual
permission fixes — Docker initializes the volume from the image, preserving
the `chown` performed in the Dockerfile.

## Automatic Detection of Pre-existing Databases

The dbs-server now includes intelligent detection of pre-existing databases:

### On Startup, the Server:

1. **Checks for existing database tarballs** in `$NC_CONFIG_ROOT/dbs/`
   - Looks for files matching pattern: `YYYY-MM-DD.tar.gz`
   - Validates corresponding JSON metadata exists

2. **If databases found:**
   - Logs: `Found existing databases (version: YYYY-MM-DD)`
   - Uses them as the initial revision
   - Creates `latest` symlinks automatically
   - **Skips initial rebuild** (saves time and resources)
   - Continues with scheduled nightly rebuilds

3. **If no databases found:**
   - Logs: `No existing databases found. Generating initial databases...`
   - Performs initial rebuild
   - Creates versioned tarballs and metadata
   - Starts serving

## Creating Database Packages

### Using pack-dbs-tarball Command

Netcap includes a `pack-dbs-tarball` command to create server-ready database packages:

```bash
# Pack databases from default location (~/.config/netcap/dbs)
zeus pack-dbs-tarball

# Pack with custom output directory
zeus pack-dbs-tarball -o ./release

# Pack from custom database directory
zeus pack-dbs-tarball -d ./netcap-dbs

# Pack with custom version
zeus pack-dbs-tarball -v 2024-01-15

# Use environment variables
DBS_VERSION=2024-01-15 zeus pack-dbs-tarball
```

This creates:
- `YYYY-MM-DD.tar.gz` - Versioned database tarball
- `YYYY-MM-DD.json` - Metadata (version, size, creation time)
- `latest.tar.gz` - Symlink/copy to latest version
- `latest.json` - Symlink/copy to latest metadata

The generated package is ready to mount directly to dbs-server.

## Use Cases

### Use Case 1: Share Databases Between Instances

Transfer databases from one dbs-server to another:

```bash
# On source server - export databases
docker cp netcap-dbs-server:/data/netcap-dbs-server/dbs /tmp/dbs-export

# Or use pack-dbs-tarball to create a package
zeus pack-dbs-tarball -d /usr/local/etc/netcap/dbs -o /tmp

# On target host
mkdir -p /path/to/host/netcap-dbs-server/dbs
cp /tmp/dbs-export/* /path/to/host/netcap-dbs-server/dbs/

# Start new server with mounted databases
docker run -d \
  --name netcap-dbs-server \
  -p 8080:8080 \
  -v /path/to/host/netcap-dbs-server:/data/netcap-dbs-server \
  dreadl0ck/netcap-dbs-server:latest
```

### Use Case 2: Fast Startup with Pre-downloaded Databases

Skip the initial rebuild by providing pre-built databases:

```bash
# Download databases from production server
curl -o /tmp/2024-01-15.tar.gz http://dbs.netcap.io/dbs/latest.tar.gz
curl -o /tmp/2024-01-15.json http://dbs.netcap.io/dbs/latest.json

# Prepare host directory
mkdir -p /data/netcap-dbs-server/dbs
cp /tmp/2024-01-15.* /data/netcap-dbs-server/dbs/

# Start server - it will use these immediately
docker run -d \
  --name netcap-dbs-server \
  -p 8080:8080 \
  -v /data/netcap-dbs-server:/data/netcap-dbs-server \
  dreadl0ck/netcap-dbs-server:latest
```

### Use Case 3: Development with Local Databases

Mount local databases for development/testing:

```bash
# Generate databases locally
cd /path/to/netcap
net util -generate-dbs

# Pack them for the server
zeus pack-dbs-tarball -d /usr/local/etc/netcap/dbs -o ./dbs-package

# Mount the package to the server
docker run -d \
  --name netcap-dbs-server-dev \
  -p 8080:8080 \
  -v $(pwd)/dbs-package:/data/netcap-dbs-server/dbs \
  dreadl0ck/netcap-dbs-server:latest
```

### Use Case 4: Persistent Storage Across Container Restarts

Use Docker volumes for persistence:

```bash
# Create named volume
docker volume create netcap-dbs-data

# First run - generates databases
docker run -d \
  --name netcap-dbs-server \
  -p 8080:8080 \
  -v netcap-dbs-data:/data \
  dreadl0ck/netcap-dbs-server:latest

# Wait for initial build...

# Stop and remove container
docker stop netcap-dbs-server
docker rm netcap-dbs-server

# Start new container - reuses existing databases!
docker run -d \
  --name netcap-dbs-server \
  -p 8080:8080 \
  -v netcap-dbs-data:/data \
  dreadl0ck/netcap-dbs-server:latest
```

## Docker Compose Example

```yaml
version: '3.8'

services:
  netcap-dbs-server:
    image: dreadl0ck/netcap-dbs-server:latest
    container_name: netcap-dbs-server
    ports:
      - "8080:8080"
    volumes:
      # Option 1: Named volume (managed by Docker)
      - netcap-dbs-data:/data
      
      # Option 2: Bind mount (direct host path)
      # - /path/on/host/netcap-dbs-server:/data/netcap-dbs-server
    environment:
      - NC_CONFIG_ROOT=/data/netcap-dbs-server
      - TZ=UTC
    restart: unless-stopped

volumes:
  netcap-dbs-data:
```

## Verification

After starting the container with mounted databases:

```bash
# Check logs for detection message
docker logs netcap-dbs-server | grep "existing databases"

# Expected output:
# Found existing databases (version: 2024-01-15)
# Using existing databases as initial revision

# Verify health endpoint
curl http://localhost:8080/health

# Check available versions
curl http://localhost:8080/dbs/list
```

## Benefits

1. **Faster Startup**: Skip initial rebuild (can save hours depending on database size)
2. **Consistency**: Ensure all servers start with same database version
3. **Disaster Recovery**: Quickly restore service with backed-up databases
4. **Resource Efficiency**: Reduce CPU/network usage on startup
5. **Offline Deployment**: Deploy servers without internet access for database generation

## Technical Implementation

The server includes these new functions (in `dbs/server.go`):

- `checkExistingDatabases()`: Scans for and validates existing database files
- `ensureLatestLinks()`: Creates symlinks/copies for `latest` version
- `createInitialTarballFromExisting()`: Converts raw DB files to tarball format

The `Start()` function now:
1. Checks for existing databases before initial rebuild
2. Uses detected version if found
3. Creates necessary symlinks
4. Proceeds with normal operation

## Troubleshooting

### Databases Not Detected

**Symptom**: Server rebuilds despite mounted databases

**Solutions**:
- Verify file naming: Must match `YYYY-MM-DD.tar.gz` pattern
- Check both `.tar.gz` and `.json` files exist
- Ensure `NC_CONFIG_ROOT` points to correct directory
- Check file permissions (readable by container user)

### Permission Issues

**Symptom**: Cannot write to mounted directory; container fails to start with
`dbs directory not writable: ...`, or scheduled rebuild logs
`mkdir ...: permission denied`.

See the [Permissions (Bind Mounts)](#permissions-bind-mounts) section for the
full explanation. Quick fix:

```bash
# Fix permissions on host (UID/GID 1000 = netcap user inside the container)
sudo chown -R 1000:1000 /path/to/host/netcap-dbs-server
sudo chmod -R u+rwX,g+rwX /path/to/host/netcap-dbs-server

# Or run container as your host user
docker run --user "$(id -u):$(id -g)" ...
```

### Symlink Issues

**Symptom**: Latest links not created

**Solution**: The server automatically falls back to copying files if symlinks fail (e.g., on some filesystems).

## See Also

- [docker/dbs-server/README.md](README.md) - Complete DBS server documentation
- [dbs/README.md](../README.md) - Database overview and usage
- [dbs/SERVER_IMPLEMENTATION.md](../SERVER_IMPLEMENTATION.md) - Technical implementation details

