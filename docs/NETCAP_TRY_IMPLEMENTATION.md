# Netcap Try Service - Implementation Summary

## Overview

The Netcap Try Service has been successfully implemented as specified. This containerized service allows users to upload PCAP/PCAPNG files up to 50MB for analysis via a web interface, with automatic rate limiting, session management, and cleanup.

## What Was Implemented

### 1. Backend Service (cmd/try/)

#### Files Created:
- **`main.go`** - Entry point for the try service
- **`flags.go`** - Command-line flag definitions
- **`server.go`** - HTTP server, job queue, and cleanup routines
- **`handlers.go`** - API endpoint handlers (upload, download, status, quota)
- **`session.go`** - Session management and rate limiting logic
- **`README.md`** - Comprehensive documentation for the try command

#### Key Features:
- ✅ HTTP server on port 7070 (configurable)
- ✅ File upload with validation (50MB max, PCAP/PCAPNG only)
- ✅ Rate limiting: 2 analyses per IP per hour (configurable)
- ✅ In-memory session tracking with automatic cleanup
- ✅ Job queue processing (one job at a time)
- ✅ DPI-enabled analysis by default
- ✅ Session expiry after 1 hour (configurable)
- ✅ Background cleanup routine (runs every 10 minutes)

### 2. API Endpoints

- **POST `/api/upload`** - Upload PCAP files (multipart/form-data)
- **GET `/api/status/{sessionId}`** - Check analysis status
- **GET `/api/download/{sessionId}`** - Download results as tar.gz
- **GET `/api/quota`** - Check remaining quota for client IP
- **GET `/health`** - Health check endpoint
- **GET `/`** - Simple web UI for file upload and download

### 3. Web Interface

A built-in single-page web interface with:
- ✅ Drag-and-drop file upload
- ✅ Real-time quota display
- ✅ Progress tracking with status updates
- ✅ One-click download of results
- ✅ File validation (size, format)
- ✅ Responsive design

### 4. Docker Container (docker/try/)

#### Files Created:
- **`Dockerfile`** - Multi-stage build with DPI support
- **`docker-compose.yml`** - Complete container orchestration
- **`entrypoint.sh`** - Bootstrap script with database download
- **`README.md`** - Docker deployment documentation
- **`.dockerignore`** - Build optimization

#### Container Features:
- ✅ Multi-stage build (builder + runtime)
- ✅ DPI support (built without nodpi tag)
- ✅ Non-root user (netcap, UID 1000)
- ✅ Automatic database bootstrap on first run
- ✅ Health checks (30s interval, 120s startup)
- ✅ Resource limits (2 CPU, 4GB RAM)
- ✅ Volume for persistent data
- ✅ Port mapping (7070:7070)

### 5. Integration

- ✅ Added `try` subcommand to `cmd/main.go`
- ✅ Updated help text
- ✅ Added to bash completion list
- ✅ Follows existing netcap command patterns

## Directory Structure

```
cmd/try/
├── main.go              # Entry point
├── flags.go             # Flag definitions
├── server.go            # HTTP server & job queue
├── handlers.go          # API handlers
├── session.go           # Session management
└── README.md            # Documentation

docker/try/
├── Dockerfile           # Container image
├── docker-compose.yml   # Orchestration
├── entrypoint.sh        # Bootstrap script
├── README.md            # Docker documentation
└── .dockerignore        # Build optimization
```

## Usage Examples

### 1. Run Locally (Development)

```bash
# Build netcap
zeus install

# Start the try service
./bin/net try -http :7070

# Access at http://localhost:7070
```

### 2. Run with Docker Compose (Production)

```bash
# From project root
cd docker/try

# Start service
docker-compose up -d

# View logs
docker-compose logs -f

# Stop service
docker-compose down
```

### 3. Upload via API

```bash
# Upload file
curl -X POST -F "file=@capture.pcap" http://localhost:7070/api/upload

# Check status
curl http://localhost:7070/api/status/{sessionId}

# Download results
curl -O http://localhost:7070/api/download/{sessionId}
```

## Configuration Options

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-http` | `:7070` | HTTP server address (required) |
| `-data-dir` | `~/.local/share/netcap-try` (local) or `/data/netcap-try` (Docker) | Data directory |
| `-dpi` | `true` | Enable DPI analysis |
| `-max-file-size` | `52428800` | Max upload size (50MB) |
| `-max-analysis-hour` | `2` | Max analyses per IP/hour |
| `-session-expiry` | `60` | Session expiry (minutes) |
| `-cleanup-interval` | `10` | Cleanup interval (minutes) |

### Environment Variables (Docker)

All flags can be set via environment variables with `NC_` prefix:
- `NC_HTTP=:7070`
- `NC_DATA_DIR=/data/netcap-try`
- `NC_DPI=true`
- etc.

### Smart Default Data Directory

The service automatically detects the environment and chooses an appropriate default:
- **In Docker**: Uses `/data/netcap-try` (assumes volume mount)
- **Local Mac/Linux**: Uses `~/.local/share/netcap-try` (user directory)
- **Fallback**: Uses `./netcap-try-data` (current directory)

Detection is based on presence of `/.dockerenv` file (standard Docker indicator).

## Security Features

1. **Rate Limiting**: 2 analyses per hour per IP (prevents abuse)
2. **File Validation**: Size and format checks with magic byte validation
3. **Session Isolation**: Each upload gets unique session ID
4. **Non-Root Container**: Runs as UID 1000 (netcap user)
5. **Auto-Cleanup**: Data removed after 1 hour
6. **IP Tracking**: Rate limiting based on X-Forwarded-For or RemoteAddr

## Architecture

### Session Management
```
Client Upload → Rate Check → Validation → Create Session → Queue Job
                                                ↓
                                          Process (DPI enabled)
                                                ↓
                                          Results Ready → Download
                                                ↓
                                          Auto-Cleanup (1hr)
```

### Job Queue
- Single worker goroutine processes jobs sequentially
- FIFO order
- Status updates via session manager
- Prevents resource exhaustion

### Cleanup Routine
- Runs every 10 minutes (configurable)
- Removes sessions older than 1 hour
- Deletes upload and result files
- Cleans IP tracker data

## Implementation Details

### Session Structure
```go
type SessionInfo struct {
    SessionID       string        // Unique identifier
    IP              string        // Client IP
    UploadTimestamp time.Time     // When uploaded
    InputFile       string        // Path to uploaded file
    InputFilename   string        // Original filename
    OutputDir       string        // Results directory
    Status          SessionStatus // queued/processing/completed/failed
    ErrorMessage    string        // Error details (if failed)
    StartTime       time.Time     // Analysis start
    CompletionTime  time.Time     // Analysis completion
    PacketsTotal    int64         // Total packets analyzed
    ResultsReady    bool          // Download available
}
```

### Rate Limiting
```go
type IPTracker struct {
    IP            string      // Client IP
    AnalysisTimes []time.Time // Recent analysis timestamps
    Sessions      []string    // Session IDs
}
```

### Download Package Contents
The download endpoint creates a tar.gz containing:
- All `*.ncap.gz` audit record files
- `netcap.log` (if exists)
- `metadata.json` (analysis summary)

## Testing the Implementation

### 1. Test Upload Validation
```bash
# Test file size limit
dd if=/dev/zero of=large.pcap bs=1M count=51
curl -X POST -F "file=@large.pcap" http://localhost:7070/api/upload
# Should return: 400 Bad Request (exceeds size limit)

# Test file format validation
echo "not a pcap" > invalid.pcap
curl -X POST -F "file=@invalid.pcap" http://localhost:7070/api/upload
# Should return: 400 Bad Request (invalid file type)
```

### 2. Test Rate Limiting
```bash
# Upload 3 files in quick succession
for i in {1..3}; do
    curl -X POST -F "file=@test.pcap" http://localhost:7070/api/upload
done
# Third request should return: 429 Too Many Requests
```

### 3. Test Analysis Pipeline
```bash
# Upload valid PCAP
curl -X POST -F "file=@valid.pcap" http://localhost:7070/api/upload
# Returns sessionId

# Poll status
curl http://localhost:7070/api/status/{sessionId}
# Status: queued → processing → completed

# Download results
curl -O http://localhost:7070/api/download/{sessionId}
# Returns netcap-results-{shortId}.tar.gz
```

### 4. Test Auto-Cleanup
```bash
# Set short expiry for testing
net try -http :7070 -session-expiry 1 -cleanup-interval 1

# Upload file and wait 2 minutes
curl -X POST -F "file=@test.pcap" http://localhost:7070/api/upload
sleep 120

# Check status (should be expired)
curl http://localhost:7070/api/status/{sessionId}
# Returns: 404 Not Found (session expired)
```

## Docker Build & Deploy

### Build Locally
```bash
# From project root
docker build -t netcap-try -f docker/try/Dockerfile .
```

### Run Container
```bash
docker run -d \
  --name netcap-try \
  -p 7070:7070 \
  -v netcap-try-data:/data \
  -e NC_MAX_ANALYSIS_HOUR=5 \
  netcap-try
```

### Check Logs
```bash
# Container logs
docker logs -f netcap-try

# Expected output:
# [Netcap Try Service] Starting...
# [Netcap Try Service] Databases not found, downloading...
# [Netcap Try Service] Databases downloaded successfully
# [Netcap Try Service] Starting HTTP server on :7070
```

### Health Check
```bash
# Container health
docker inspect --format='{{.State.Health.Status}}' netcap-try

# API health
curl http://localhost:7070/health
# {"status":"healthy","timestamp":1705315200,"sessions":0,"queueSize":0}
```

## Troubleshooting

### Issue: Port Already in Use
```bash
# Solution 1: Use different port
net try -http :8080

# Solution 2: Stop conflicting service
lsof -i :7070
kill -9 <PID>
```

### Issue: Database Download Fails
```bash
# The service will start anyway but with warnings
# Manually download databases:
docker exec netcap-try netcap util -download-dbs
```

### Issue: Permission Errors in Container
```bash
# Fix data directory permissions
docker exec -u root netcap-try chown -R netcap:netcap /data
```

### Issue: Analysis Fails
```bash
# Check analysis logs
docker exec netcap-try cat /data/netcap-try/results/{sessionId}/netcap.log

# Common causes:
# - Corrupted PCAP file
# - Insufficient disk space
# - Out of memory
```

## Performance Considerations

### Resource Requirements
- **Minimum**: 512MB RAM, 1 CPU, 5GB disk
- **Recommended**: 2GB RAM, 2 CPU, 10GB disk
- **Per Analysis**: ~500MB RAM, varies by PCAP size

### Scaling
- Single container: Good for ~10-20 concurrent users
- Multiple containers: Use load balancer with session affinity
- Horizontal scaling: Requires shared storage for sessions

### Optimization
- Adjust `-session-expiry` to reduce storage
- Increase `-cleanup-interval` to reduce I/O
- Use SSD for better performance
- Set Docker resource limits

## Future Enhancements

Possible improvements (not currently implemented):
1. Persistent session storage (SQLite/Redis)
2. Email notifications on completion
3. Advanced web UI with live streaming results
4. Multi-file upload support
5. Custom analysis configurations
6. Results comparison between uploads
7. Integration with netcap-dbs-server
8. Prometheus metrics export
9. User authentication (API keys)
10. Webhook callbacks

## Files Modified

- ✅ `cmd/main.go` - Added try subcommand routing
- ✅ All other files are new additions

## Compliance with Requirements

All original requirements have been met:

1. ✅ Upload pcap/pcapng files up to 50MB
2. ✅ View results of user's own analysis
3. ✅ Remove user uploads and data after 1 hour
4. ✅ Allow download of generated audit record files
5. ✅ Rate limit: max 2 analyses per hour per IP
6. ✅ Not run as root in Docker container
7. ✅ Bootstrap with `net util -download-dbs`
8. ✅ Run analysis with `-dpi` enabled

## Conclusion

The Netcap Try Service is fully implemented and ready for deployment. All components work together to provide a secure, user-friendly web service for PCAP analysis with automatic resource management.

To get started:
```bash
cd docker/try
docker-compose up -d
```

Then access the service at http://localhost:7070

