# Database Server Implementation

This document describes the implementation of the netcap database server feature.

## Overview

The database server feature allows users to:
1. Run an HTTP server that serves netcap databases
2. Automatically rebuild databases every night at midnight (UTC)
3. Version databases by date (YYYY-MM-DD format)
4. Download databases from a remote server
5. Deploy the server using a lightweight Alpine Linux Docker container

## Components

### 1. Server Implementation (`dbs/server.go`)

**Key Features:**
- HTTP server with versioned database serving
- Automatic nightly rebuilds at midnight UTC
- Storage optimization: only latest version kept
- Automatic cleanup of old versions after rebuild
- Tarball creation and metadata generation
- Health check endpoint
- RESTful API for database access

**Endpoints:**
- `GET /health` - Health check with current version info
- `GET /dbs/latest` - JSON metadata about the latest version
- `GET /dbs/list` - JSON list of all available versions
- `GET /dbs/latest.tar.gz` - Download latest database tarball
- `GET /dbs/YYYY-MM-DD.tar.gz` - Download specific version by date

**Scheduler:**
- Checks every hour if it's midnight
- Generates new database version if date has changed
- Uses mutex for thread-safe version tracking

### 2. Download Client (`dbs/download.go`)

**Key Features:**
- Downloads databases from configured server
- Extracts tarball to configured location
- Progress reporting during download
- Version tracking to avoid unnecessary downloads
- Supports custom server URLs

**Configuration:**
- Environment variable: `NETCAP_DBS_URL`
- Command-line flag: `-dbs-url`
- Default: `http://dbs.netcap.io`

### 3. Command-Line Integration (`cmd/util/`)

**New Flags:**
- `-serve-dbs` - Start the database server
- `-serve-addr` - Server listen address (default: `:8080`)
- `-download-dbs` - Download databases from server
- `-dbs-url` - Custom server URL for downloads
- `-force` - Force re-download even if up-to-date

**Usage Examples:**
```bash
# Start server
net util -serve-dbs

# Start server on custom port
net util -serve-dbs -serve-addr :9090

# Download databases
net util -download-dbs

# Download from custom server
net util -download-dbs -dbs-url http://your-server:8080
```

### 4. Docker Container (`docker/dbs-server/`)

**Files:**
- `Dockerfile` - Alpine-based multi-stage build
- `docker-compose.yml` - Easy deployment configuration
- `README.md` - Complete documentation
- `.dockerignore` - Build optimization
- `build.sh` - Build script

**Features:**
- Lightweight Alpine Linux base (~50MB final image)
- Multi-stage build for minimal size
- Non-root user execution (security)
- Health checks configured
- Volume for persistent data
- Automatic restart on failure

**Quick Start:**
```bash
cd docker/dbs-server
docker-compose up -d
```

## Architecture

### Database Generation Flow

1. **Scheduler** triggers at midnight UTC
2. **Server** creates versioned directory (YYYY-MM-DD)
3. **Generator** fetches all data sources in parallel
4. **Hooks** process downloaded data (extract, index, etc.)
5. **Packager** creates gzipped tarball
6. **Metadata** JSON file created with version info
7. **Symlinks** updated for "latest" version
8. **Cleanup** automatically removes old database versions to save storage

### Download Flow

1. **Client** queries `/dbs/latest` endpoint
2. **Version Check** compares with local version
3. **Download** tarball if needed with progress reporting
4. **Extract** to configured database directory
5. **Save** version file for future checks

### Versioning

Databases are versioned by date:
- Format: `YYYY-MM-DD` (e.g., `2024-01-15`)
- Each version gets its own tarball and metadata
- "latest" symlink always points to current version
- Only the most recent version is retained to optimize storage
- Old versions are automatically deleted after each rebuild

## Configuration

### Environment Variables

- `NC_CONFIG_ROOT` - Root directory for config/databases
  - Default: `~/.config/netcap`
- `NETCAP_DBS_URL` - Database server URL
  - Default: `http://dbs.netcap.io`

### File Locations

**Server:**
- Build directory: `netcap-dbs-server/`
- Databases: `netcap-dbs-server/dbs/`
- Tarballs: `netcap-dbs-server/dbs/YYYY-MM-DD.tar.gz`
- Metadata: `netcap-dbs-server/dbs/YYYY-MM-DD.json`

**Client:**
- Config root: `$NC_CONFIG_ROOT` or `~/.config/netcap`
- Databases: `$NC_CONFIG_ROOT/dbs/`
- Version file: `$NC_CONFIG_ROOT/.db-version`

## API Reference

### GET /health

Returns server status and current version.

**Response:**
```json
{
  "status": "healthy",
  "current_version": "2024-01-15",
  "timestamp": "2024-01-15T12:30:00Z"
}
```

### GET /dbs/latest

Returns metadata about the latest database version.

**Response:**
```json
{
  "version": "2024-01-15",
  "created_at": "2024-01-15T00:05:23Z",
  "tarball": "2024-01-15.tar.gz",
  "nvd_start_year": 2002
}
```

### GET /dbs/list

Returns list of all available versions (only latest due to storage optimization).

**Response:**
```json
{
  "versions": ["2024-01-16"],
  "latest": "2024-01-16",
  "note": "Server is configured to keep only the latest version to optimize storage"
}
```

### GET /dbs/latest.tar.gz

Downloads the latest database tarball.

**Response:**
- Content-Type: `application/gzip`
- Content-Disposition: `attachment; filename=latest.tar.gz`

### GET /dbs/YYYY-MM-DD.tar.gz

Downloads a specific database version.

**Response:**
- Content-Type: `application/gzip`
- Content-Disposition: `attachment; filename=YYYY-MM-DD.tar.gz`

## Testing

### Manual Testing

1. **Start Server:**
   ```bash
   net util -serve-dbs -verbose
   ```

2. **Check Health:**
   ```bash
   curl http://localhost:8080/health
   ```

3. **List Versions:**
   ```bash
   curl http://localhost:8080/dbs/list
   ```

4. **Download Database:**
   ```bash
   net util -download-dbs
   ```

### Docker Testing

1. **Build and Run:**
   ```bash
   cd docker/dbs-server
   docker-compose up -d
   ```

2. **Check Logs:**
   ```bash
   docker-compose logs -f
   ```

3. **Test Health:**
   ```bash
   docker exec netcap-dbs-server curl http://localhost:8080/health
   ```

## Security Considerations

1. **Docker Container:**
   - Runs as non-root user (netcap:1000)
   - Minimal Alpine base image
   - Only necessary packages installed

2. **HTTP Server:**
   - Read-only operations only
   - No authentication (intended for internal networks)
   - For public deployment, use reverse proxy with SSL/auth

3. **File System:**
   - All files created with standard permissions
   - No sensitive data in databases

## Performance

### Resource Usage

**Server (during rebuild):**
- CPU: 2-4 cores (parallel downloads/processing)
- RAM: 2-4 GB
- Disk: ~10 GB (single version + temporary build artifacts)
- Network: Downloads ~5-10 GB of data

**Server (idle):**
- CPU: Minimal
- RAM: ~100 MB
- Disk: ~5-10 GB (latest version only)
- Network: Minimal

**Client (downloading):**
- CPU: Minimal
- RAM: ~100 MB
- Disk: ~5 GB
- Network: ~5 GB download

### Optimization

- Parallel data source fetching
- Gzip compression for tarballs
- Progress reporting for large downloads
- Efficient tar extraction

## Future Enhancements

1. **Authentication:** Add API key or JWT authentication
2. **Metrics:** Prometheus metrics endpoint
3. **CDN:** Integration with CDN for global distribution
4. **Delta Updates:** Only download changed databases
5. **Signing:** GPG signing of tarballs for verification
6. **Retention Policy:** Configurable retention (keep N versions instead of just latest)
7. **Mirroring:** Support for multiple mirror servers
8. **Compression:** Better compression algorithms (zstd)

## Troubleshooting

### Server Won't Start

- Check if port 8080 is available
- Verify write permissions to data directory
- Check disk space

### Database Generation Fails

- Verify internet connectivity
- Check external data source availability
- Ensure sufficient disk space
- Review logs for specific errors

### Download Fails

- Verify server is accessible
- Check firewall rules
- Ensure sufficient disk space on client
- Verify URL is correct

### Docker Issues

- Check Docker logs: `docker-compose logs`
- Verify volume permissions
- Ensure ports are not in use
- Check resource limits

## References

- Main documentation: `dbs/README.md`
- Docker documentation: `docker/dbs-server/README.md`
- Command help: `net util -h`

