# Netcap Database Server Docker Container

This lightweight Alpine Linux container runs the Netcap database server, which automatically rebuilds and serves the databases with nightly updates.

## Features

- **Automatic Nightly Rebuilds**: Databases are automatically regenerated every night at midnight (UTC)
- **Versioned Databases**: Each build is versioned by date (YYYY-MM-DD format)
- **Storage Optimized**: Only the most recent version is kept to prevent storage issues
- **HTTP API**: Simple HTTP endpoints for downloading databases
- **Health Checks**: Built-in health check endpoint for monitoring
- **Lightweight**: Based on Alpine Linux for minimal resource usage
- **Persistent Storage**: Uses volumes for database persistence

## Quick Start

### Using Zeus Build System (Recommended for Development)

```bash
# Build the container locally
zeus build-dbs-server

# Build and push to registry
NETCAP_PUSH_IMAGES=true zeus build-dbs-server

# See BUILD.md for detailed build instructions
```

### Using Docker Compose (Recommended for Deployment)

```bash
# From the project root
cd docker/dbs-server

# Start the service
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

### Using Docker Directly

```bash
# Build the image
docker build -t netcap-dbs-server -f docker/dbs-server/Dockerfile .

# Run the container
docker run -d \
  --name netcap-dbs-server \
  -p 8080:8080 \
  -v netcap-dbs-data:/data \
  -e TZ=UTC \
  netcap-dbs-server
```

### Using Pre-built Image from Registry

```bash
# Pull from Docker Hub
docker pull dreadl0ck/netcap-dbs-server:latest

# Run the container
docker run -d \
  --name netcap-dbs-server \
  -p 8080:8080 \
  -v netcap-dbs-data:/data \
  dreadl0ck/netcap-dbs-server:latest
```

## API Endpoints

Once running, the server provides the following endpoints:

### Health Check
```bash
curl http://localhost:8080/health
```

Returns the server status and current database version.

### Download Latest Database
```bash
curl -o netcap-dbs.tar.gz http://localhost:8080/dbs/latest.tar.gz
```

Downloads the latest database tarball.

### Get Latest Version Metadata
```bash
curl http://localhost:8080/dbs/latest
```

Returns JSON metadata about the latest database version.

### List Available Versions
```bash
curl http://localhost:8080/dbs/list
```

Returns a JSON list of all available database versions.

### Download Specific Version
```bash
curl -o netcap-dbs.tar.gz http://localhost:8080/dbs/2024-01-15.tar.gz
```

Downloads a specific database version by date.

## Client Usage

To download databases from a running server using the `netcap` command:

```bash
# Download from default URL (dbs.netcap.io)
net util -download-dbs

# Download from custom URL
net util -download-dbs -dbs-url http://your-server:8080

# Download from custom URL using environment variable
export NETCAP_DBS_URL=http://your-server:8080
net util -download-dbs

# Force re-download even if already up to date
net util -download-dbs -force
```

## Database Storage

### Storage Location

The dbs-server stores databases in the following structure:

```
/data/netcap-dbs-server/          # Root directory (controlled by NC_CONFIG_ROOT)
├── dbs/                           # Database storage directory
│   ├── 2024-01-15.tar.gz         # Versioned database tarball
│   ├── 2024-01-15.json           # Metadata for version
│   ├── latest.tar.gz             # Symlink to latest version
│   └── latest.json               # Symlink to latest metadata
└── build/                         # Temporary build directory
```

**Key Paths:**
- Container: `/data/netcap-dbs-server/dbs/` - Where versioned databases are stored
- Host: Mapped via Docker volume (e.g., `netcap-dbs-data:/data`)

### Mounting Pre-existing Databases

You can provide pre-existing databases to the server by mounting them from the host. The server will automatically detect and use them as the initial revision, skipping the initial rebuild.

**Creating Database Packages:**

Use the `pack-dbs-tarball` Zeus command to create server-ready packages:

```bash
# Pack databases from default location (~/.config/netcap/dbs)
zeus pack-dbs-tarball -o ./output

# This creates versioned tarball, metadata, and latest symlinks
```

See `MOUNTING_DATABASES.md` for detailed examples and use cases.

#### Permission Setup for Host Directories

**Important:** When mounting host directories, you must set the correct permissions for the container's `netcap` user (UID 1000, GID 1000).

```bash
# Create the directory on the host
mkdir -p /mnt/storage/netcap-dbs-server

# Set ownership to UID 1000, GID 1000 (the netcap user inside the container)
chown -R 1000:1000 /mnt/storage/netcap-dbs-server

# Alternatively, use Docker to set permissions
docker run --rm -v /mnt/storage/netcap-dbs-server:/data alpine sh -c "chown -R 1000:1000 /data"
```

**Note:** The `netcap` user only exists inside the container, so you must use the numeric UID/GID (1000:1000) on the host system.

#### Option 1: Mount Pre-generated Database Tarballs

If you have pre-generated database tarballs (e.g., from another dbs-server instance):

```bash
# Prepare your databases directory on the host
mkdir -p /path/on/host/netcap-dbs-server/dbs

# Set correct permissions (REQUIRED)
chown -R 1000:1000 /path/on/host/netcap-dbs-server

# Copy your database tarballs
cp 2024-01-15.tar.gz /path/on/host/netcap-dbs-server/dbs/
cp 2024-01-15.json /path/on/host/netcap-dbs-server/dbs/

# Run container with mounted databases
docker run -d \
  --name netcap-dbs-server \
  -p 8080:8080 \
  -v /path/on/host/netcap-dbs-server:/data/netcap-dbs-server \
  -e NC_CONFIG_ROOT=/data/netcap-dbs-server \
  dreadl0ck/netcap-dbs-server:latest
```

The server will:
1. Detect the existing database files
2. Use them as the initial revision without rebuilding
3. Log: `Found existing databases (version: 2024-01-15)`
4. Create `latest.tar.gz` and `latest.json` links automatically
5. Continue with nightly rebuilds as scheduled

#### Option 2: Mount Raw Database Files

If you have raw database files (not tarballed):

```bash
# Prepare your databases directory with raw files
mkdir -p /path/on/host/netcap-dbs

# Set correct permissions (REQUIRED)
chown -R 1000:1000 /path/on/host/netcap-dbs

# Copy your database files
cp *.csv *.json *.mmdb /path/on/host/netcap-dbs/

# Run container with mounted databases
docker run -d \
  --name netcap-dbs-server \
  -p 8080:8080 \
  -v /path/on/host/netcap-dbs:/data/netcap-dbs-server/dbs \
  -e NC_CONFIG_ROOT=/data/netcap-dbs-server \
  dreadl0ck/netcap-dbs-server:latest
```

The server will:
1. Detect raw database files in the mounted location
2. Create an initial tarball from them
3. Use this as the first served version
4. Continue with nightly rebuilds

#### Option 3: Using Docker Compose with Pre-existing Databases

```yaml
# docker-compose.yml
version: '3.8'

services:
  netcap-dbs-server:
    image: dreadl0ck/netcap-dbs-server:latest
    container_name: netcap-dbs-server
    ports:
      - "8080:8080"
    volumes:
      # Mount pre-existing databases from host
      - /path/on/host/netcap-dbs-server:/data/netcap-dbs-server
    environment:
      - NC_CONFIG_ROOT=/data/netcap-dbs-server
      - TZ=UTC
    restart: unless-stopped
```

Then run:
```bash
docker-compose up -d
```

### Verifying Mounted Databases

After starting the container with mounted databases, check the logs:

```bash
# View logs
docker logs netcap-dbs-server

# Look for these messages:
# "Found existing databases (version: 2024-01-15)"
# "Using existing databases as initial revision"
```

You can also check the health endpoint:

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "2024-01-15",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### Backup and Restore

#### Backup Databases

```bash
# Create backup of all database versions
docker cp netcap-dbs-server:/data/netcap-dbs-server/dbs /path/to/backup/

# Or backup the entire volume
docker run --rm \
  -v netcap-dbs-data:/data \
  -v /path/to/backup:/backup \
  alpine tar czf /backup/netcap-dbs-backup.tar.gz /data
```

#### Restore Databases

```bash
# Stop the container
docker stop netcap-dbs-server

# Restore from backup
docker run --rm \
  -v netcap-dbs-data:/data \
  -v /path/to/backup:/backup \
  alpine tar xzf /backup/netcap-dbs-backup.tar.gz -C /

# Start the container
docker start netcap-dbs-server
```

## Environment Variables

- `NC_CONFIG_ROOT`: Root directory for netcap configuration and databases (default: `/data/netcap-dbs-server`)
- `NETCAP_DBS_URL`: URL for downloading databases (default: `http://dbs.netcap.io`)
- `TZ`: Timezone for the container (default: `UTC`)

## Configuration

### Custom Port

To run on a different port:

```yaml
# docker-compose.yml
ports:
  - "9090:8080"
```

Or with Docker:

```bash
docker run -d -p 9090:8080 netcap-dbs-server
```

### Custom NVD Start Year

To index NVD vulnerabilities from a specific year:

```yaml
# docker-compose.yml
command: ["netcap", "util", "-serve-dbs", "-serve-addr", ":8080", "-nvd-start-year", "2010", "-verbose"]
```

## Volumes

- `/data`: Persistent storage for generated databases and build artifacts

## Resource Requirements

**Minimum:**
- CPU: 1 core
- RAM: 2GB
- Disk: 10GB

**Recommended:**
- CPU: 2 cores
- RAM: 4GB
- Disk: 15GB (single version + temporary build artifacts)

**Note:** The server automatically cleans up old database versions after each rebuild, keeping only the latest version to optimize storage usage.

## Monitoring

### Health Checks

The container includes built-in health checks:

```bash
# Check container health
docker inspect --format='{{.State.Health.Status}}' netcap-dbs-server

# View health check logs
docker inspect --format='{{range .State.Health.Log}}{{.Output}}{{end}}' netcap-dbs-server
```

### Logs

```bash
# Follow logs
docker-compose logs -f

# View last 100 lines
docker-compose logs --tail=100
```

## Troubleshooting

### Permission Denied Errors

If you see errors like `mkdir /data/netcap-dbs-server/build: permission denied`:

1. **Fix permissions on named Docker volume:**
   ```bash
   docker run --rm -v netcap-dbs-data:/data alpine sh -c "chown -R 1000:1000 /data"
   ```

2. **Fix permissions on host bind mount:**
   ```bash
   chown -R 1000:1000 /mnt/storage/netcap-dbs-server
   ```

3. **Recreate volume with correct permissions:**
   ```bash
   docker-compose down
   docker volume rm netcap-dbs-data
   docker-compose up -d
   ```

**Note:** The container runs as user `netcap` (UID 1000, GID 1000). All mounted directories must be owned by this user.

### Container Won't Start

1. Check logs: `docker-compose logs`
2. Verify port 8080 is not in use: `lsof -i :8080`
3. Ensure sufficient disk space

### Database Generation Fails

1. Check internet connectivity (required for downloading sources)
2. Verify git and git-lfs are working: `docker exec netcap-dbs-server git lfs version`
3. Check available disk space in the volume

### Download Fails from Client

1. Verify server is running: `curl http://localhost:8080/health`
2. Check firewall rules
3. Verify correct URL is configured

## Production Deployment

For production use, consider:

1. **Reverse Proxy**: Use nginx or traefik for HTTPS/SSL
2. **Authentication**: Add authentication middleware
3. **Monitoring**: Integrate with Prometheus/Grafana
4. **Backup**: Regular backups of the `/data` volume
5. **High Availability**: Run multiple instances with load balancing

### Example with Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl http2;
    server_name dbs.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## License

See the main NETCAP repository for license information.

## Support

For issues and questions, please visit: https://github.com/dreadl0ck/netcap

