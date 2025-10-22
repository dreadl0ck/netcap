# pack-dbs-tarball Command

## Overview

The `pack-dbs-tarball` Zeus command creates versioned database packages ready for distribution or mounting to dbs-server instances. It generates tarballs with metadata and symlinks that the dbs-server can automatically detect and use.

## Purpose

This command solves several important use cases:

1. **Share databases** between multiple dbs-server instances
2. **Distribute pre-built databases** to avoid rebuild time
3. **Create backups** of database versions
4. **Package databases for offline deployment**
5. **Prepare databases for Docker volume mounting**

## Usage

### Basic Usage

```bash
# Pack databases from default location (~/.config/netcap/dbs)
zeus pack-dbs-tarball

# Pack with custom output directory
zeus pack-dbs-tarball -o /path/to/output

# Pack from custom database directory
zeus pack-dbs-tarball -d /path/to/dbs

# Pack with custom version string
zeus pack-dbs-tarball -v 2024-01-15

# Use environment variables
DBS_VERSION=2024-01-15 zeus pack-dbs-tarball
```

### Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d, --dbs-dir PATH` | Path to databases directory | `~/.config/netcap/dbs` |
| `-o, --output-dir PATH` | Output directory for tarball | Current directory |
| `-v, --version DATE` | Version string (YYYY-MM-DD format) | Current date |
| `-s, --start-year YEAR` | NVD start year for metadata | 2002 |
| `-h, --help` | Show help message | - |

### Environment Variables

- `NC_CONFIG_ROOT`: Override default databases location (will use `$NC_CONFIG_ROOT/dbs`)
- `DBS_VERSION`: Default version if `-v` not specified (format: YYYY-MM-DD)
- `NVD_START_YEAR`: Default NVD start year if `-s` not specified

## Output

The command creates four files:

```
output-directory/
├── YYYY-MM-DD.tar.gz    # Versioned database tarball
├── YYYY-MM-DD.json      # Metadata JSON file
├── latest.tar.gz        # Symlink to latest tarball
└── latest.json          # Symlink to latest metadata
```

### Tarball Structure

The tarball preserves the `dbs/` directory structure:

```
YYYY-MM-DD.tar.gz
└── dbs/
    ├── service-names-port-numbers.csv
    ├── domain-whitelist.csv
    ├── ja3_fingerprints.json
    ├── GeoLite2-City.mmdb
    ├── GeoLite2-ASN.mmdb
    └── ... (all database files)
```

### Metadata Format

The JSON metadata file contains:

```json
{
  "version": "2024-01-15",
  "created_at": "2024-01-15T12:00:00Z",
  "tarball": "2024-01-15.tar.gz",
  "tarball_size_bytes": 123456789,
  "file_count": 42,
  "nvd_start_year": 2002,
  "source": "pack-dbs script"
}
```

## Workflow Examples

### Example 1: Package Locally Generated Databases

```bash
# Generate databases (goes to ~/.config/netcap/dbs by default)
cd /path/to/netcap
net util -generate-dbs

# Package them (uses default location)
zeus pack-dbs-tarball -o ./release

# Result: release/2024-01-15.tar.gz and metadata ready for distribution
```

### Example 2: Create Daily Database Snapshots

```bash
#!/bin/bash
# Daily backup script

DATE=$(date +%Y-%m-%d)
OUTPUT_DIR="/backups/netcap-dbs"

# Package current databases from default location
zeus pack-dbs-tarball -o "$OUTPUT_DIR" -v "$DATE"

# Upload to S3, etc.
aws s3 cp "$OUTPUT_DIR/$DATE.tar.gz" s3://my-bucket/netcap-dbs/
aws s3 cp "$OUTPUT_DIR/$DATE.json" s3://my-bucket/netcap-dbs/
```

### Example 3: Prepare for Docker Volume Mount

```bash
# Package databases from default location
zeus pack-dbs-tarball -o /data/netcap-dbs

# Mount to dbs-server
docker run -d \
  --name netcap-dbs-server \
  -p 8080:8080 \
  -v /data/netcap-dbs:/data/netcap-dbs-server/dbs \
  dreadl0ck/netcap-dbs-server:latest

# Server will detect and use pre-existing databases immediately
```

### Example 4: Share Between Development and Production

```bash
# Development: Generate and package databases
zeus pack-dbs-tarball -o ./release

# Copy to production server
scp ./release/2024-01-15.* prod-server:/data/netcap-dbs/

# Production: Start server with pre-packaged databases
# (on production server)
docker run -d \
  --name netcap-dbs-server \
  -p 8080:8080 \
  -v /data/netcap-dbs:/data/netcap-dbs-server/dbs \
  dreadl0ck/netcap-dbs-server:latest
```

## Integration with dbs-server

The dbs-server automatically detects and uses packaged databases:

1. **On startup**, the server scans `/data/netcap-dbs-server/dbs/` for tarballs
2. **Finds** files matching `YYYY-MM-DD.tar.gz` pattern
3. **Validates** corresponding JSON metadata exists
4. **Uses** the most recent version as initial revision
5. **Creates** `latest` symlinks if missing
6. **Skips** initial database rebuild (saves time!)
7. **Continues** with scheduled nightly rebuilds

### Server Logs When Detecting Packages

```
[INFO] Found existing databases (version: 2024-01-15)
[INFO] Using existing databases as initial revision
[INFO] Starting database server on :8080
```

## Advantages

### Time Savings

- **Initial build time**: 2-4 hours (depending on NVD data)
- **Using pre-packaged DBs**: < 1 minute to start serving
- **Benefit**: 99% reduction in startup time

### Resource Efficiency

- **No initial CPU spike** for database generation
- **No network traffic** for downloading source data
- **Lower memory usage** during startup

### Consistency

- **Same databases** across all environments
- **Known versions** with metadata tracking
- **Reproducible deployments**

## Troubleshooting

### Error: "Databases directory is empty"

**Cause**: The specified directory has no files

**Solution**:
```bash
# Verify directory has database files
ls -la /path/to/dbs

# Ensure you're pointing to the correct directory
zeus pack-dbs-tarball -d /correct/path/to/dbs
```

### Error: "Invalid version format"

**Cause**: Version string doesn't match YYYY-MM-DD pattern

**Solution**:
```bash
# Use correct date format
zeus pack-dbs-tarball -d /path/to/dbs -v 2024-01-15  # Correct
# Not: zeus pack-dbs-tarball -d /path/to/dbs -v 01-15-2024  # Wrong
```

### Symlinks Not Created

**Cause**: Filesystem doesn't support symlinks

**Behavior**: Script automatically falls back to copying files

**Result**: `latest.tar.gz` and `latest.json` are copies instead of symlinks (works fine)

## Script Location

```
zeus/scripts/pack-dbs.sh
```

The script is executed via Zeus command system:
```yaml
# zeus/commands.yml
pack-dbs-tarball:
    description: pack databases into versioned tarball for dbs-server with metadata and symlinks
    exec: zeus/scripts/pack-dbs.sh
```

## Related Commands

- `net util -generate-dbs` - Generate databases from scratch
- `net util -download-dbs` - Download databases from server
- `zeus build-dbs-server` - Build dbs-server Docker image

## See Also

- [MOUNTING_DATABASES.md](MOUNTING_DATABASES.md) - Detailed mounting guide
- [README.md](README.md) - DBS server documentation
- [../dbs/README.md](../dbs/README.md) - Database overview

